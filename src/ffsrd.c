/*
 * ffsrd — the daemon exposing Firefox's WS on /run/ffsrd/ffsr.sock.
 *
 * Role (spec):
 *   - opens the WS to the 9222 bridge and creates the session (at startup)
 *   - exposes the WS on a local Unix socket
 *   - multiplexes up to 128 simultaneous clients (id rewriting)
 *   - understands NO command: pure passthrough, only field read: "id"
 *   - returns the session before dying (session.end), never ws.close
 *
 * Flight 2 convention: ONE request per client connection — the daemon
 * closes the connection after routing the response (the CLI reads EOF).
 */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <grp.h>
#include <curl/curl.h>

/* ----------------------------------------------------------- constants */

#define MAX_CLIENTS     128              /* spec: 128 max multiplexed */
#define MAX_PENDING     1024             /* ids in flight (8/clients × 128) */
#define SOCK_PATH       "/run/ffsrd/ffsr.sock"
#define WINDOW_SOCK     "/run/ffsrd/window.sock"   /* dedicated window hash */
#define SOCK_MODE       0660             /* rw: owner + sudo group */
#define WS_URL          "ws://127.0.0.1:9222/session"
#define HANDSHAKE_TO    10000            /* ms startup/shutdown response wait */
#define LOG_PATH        "/var/lib/ffsrd/ffsrd.log"

/* ------------------------------------------------------- routing table */

typedef struct {
  int   fd;          /* -1 = free */
  Buf   in;          /* read buffer (incoming frames) */
  int   stream;      /* 1 = streaming client (session.subscribe): the
                      * connection stays open and WS events are relayed */
  time_t last_seen;  /* last activity (session timeout, 10 min) */
} Client;

typedef struct {
  int   fd;          /* destination client; -1 = the daemon itself */
  long  id_global;   /* the id substituted by the daemon (on the WS) */
  long  id_client;   /* the original client-side id (restored on reply) */
  int   used;
} Pending;

static Client clients[MAX_CLIENTS];
static Pending pending[MAX_PENDING];
static long     g_next_id = 1000;        /* global ids, never reused */
static int      listen_fd = -1;          /* ffsr.sock (BiDi stream) */
static int      window_listen_fd = -1;   /* window.sock (dedicated hash) */
static int      g_wsfd = -1;             /* active WS socket (select) */
static fd_set   g_rd;                    /* watched fds (select) */
static int      g_maxfd = -1;            /* high bound for select */

/* keepactive: inject audio heartbeat to prevent Firefox tab suspend */
#define KEEPACTIVE_S 1
static int      g_keepactive_idx = 0;
static time_t   g_keepactive_last = 0;

/* Route a complete WS message to its client (defined below, used by
 * ws_wait_daemon_response BEFORE its definition). */
static void relay_message(const char *data, size_t len);

/* curl / websocket */
static CURL  *g_curl = NULL;
static int    g_ws_alive = 0;            /* is the WS connection alive? */
static Buf    g_wsbuf;                   /* fragments received before processing */

/* Closes THE client connection (slot): close + FD_CLR + recompute g_maxfd.
 * ONLY client close point — a close without FD_CLR would leave a closed
 * fd in g_rd → select EBADF → daemon death. */
static void client_close_slot(int slot) {
  int fd = clients[slot].fd;
  if (fd < 0) return;
  close(fd);
  FD_CLR(fd, &g_rd);
  if (fd == g_maxfd) { /* recompute the high bound */
    g_maxfd = listen_fd;
    if (g_wsfd > g_maxfd) g_maxfd = g_wsfd;
    for (int i = 0; i < MAX_CLIENTS; i++)
      if (clients[i].fd > g_maxfd) g_maxfd = clients[i].fd;
  }
  clients[slot].fd = -1;
  clients[slot].stream = 0;
  clients[slot].last_seen = 0;
  buf_reset(&clients[slot].in);
  /* Purge the pending of this client: a response arriving late (slow
   * iframe, etc.) after its disconnect must NEVER be routed to the
   * recycled fd of another client — cross-corruption bug found
   * 2026-08-12 during the get child testing. */
  for (int i = 0; i < MAX_PENDING; i++)
    if (pending[i].used && pending[i].fd == fd) {
      pending[i].used = 0;
      log_msg("pending (id_global %ld) purged on disconnect", pending[i].id_global);
    }
  log_msg("client #%d disconnected", slot);
}

/* ---------------------------------------------------------------- signals */

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
  (void)sig;
  g_stop = 1;
}

/* ------------------------------------ WS owner (firefox-bin) detection */

/* Port 9222 in hex (/proc/net/tcp shows ports in hex) */
#define WS_PORT_HEX "2406"

/* Detects the UID of the WS owner (firefox-bin — the server side of the
 * 9222 connection). The daemon is already connected to the WS BEFORE
 * creating the socket: the connection therefore necessarily exists in
 * /proc/net/tcp, and the uid column on the server side (local port 9222)
 * IS the firefox-bin uid. Returns the uid (>0) or -1. */
static int detect_ws_owner_uid(void) {
  const char *files[] = { "/proc/net/tcp", "/proc/net/tcp6", NULL };
  char line[512];

  for (int f = 0; files[f]; f++) {
    FILE *fp = fopen(files[f], "r");
    if (!fp) continue;
    fgets(line, sizeof(line), fp); /* header */
    while (fgets(line, sizeof(line), fp)) {
      char local[64], rem[64], st[16], a[32], b[32];
      unsigned long retr;
      int uid;
      int n = sscanf(line, "%*d: %63s %63s %15s %31s %31s %lx %d",
                     local, rem, st, a, b, &retr, &uid);
      if (n < 7) continue;
      /* the listening side (0A) OR an established connection (01) whose
       * LOCAL port is 9222 = firefox-bin (the bridge server) */
      char *colon = strrchr(local, ':');
      if (!colon) continue;
      if (strcmp(colon + 1, WS_PORT_HEX) != 0) continue;
      if (strcmp(st, "0A") != 0 && strcmp(st, "01") != 0) continue;
      if (uid > 0) {
        fclose(fp);
        return uid;
      }
    }
    fclose(fp);
  }
  return -1;
}

/* GID of the "all admin humans" group: sudo (Debian/Ubuntu), else wheel
 * (Arch/Slackware), else root (reasonable default). */
static gid_t sudo_gid(void) {
  struct group *g = getgrnam("sudo");
  if (g) return g->gr_gid;
  g = getgrnam("wheel");
  if (g) return g->gr_gid;
  return 0;
}

/* ---------------------------------------------------------- unix socket */

/* mkdir -p equivalent: creates each path level (mode 0755), tolerates
 * EEXIST. Returns 0 or -1. */
static int mkdir_p(const char *path) {
  char tmp[512];
  size_t len = strlen(path);
  if (len >= sizeof(tmp)) return -1;
  memcpy(tmp, path, len + 1);
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
      *p = '/';
    }
  }
  if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
  return 0;
}

static int socket_unix_create(const char *path) {
  /* the daemon creates ITS socket directory (required: /run is a tmpfs,
   * purged at every boot — no manual step needed). */
  char dir[512];
  size_t len = strlen(path);
  if (len >= sizeof(dir)) { log_err("socket path too long"); return -1; }
  memcpy(dir, path, len + 1);
  char *slash = strrchr(dir, '/');
  if (slash && slash != dir) {
    *slash = '\0';
    if (mkdir_p(dir) != 0) {
      log_err("mkdir %s: %s", dir, strerror(errno));
      return -1;
    }
  }

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) { log_err("socket: %s", strerror(errno)); return -1; }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

  unlink(path);
  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    log_err("bind %s: %s", path, strerror(errno));
    close(fd);
    return -1;
  }
  chmod(path, SOCK_MODE);

  /* Ownership (decision 2026-08-11): the socket belongs to the WS OWNER
   * (firefox-bin, with whom ffsrd talks) + sudo group (the admin humans).
   * Without this chown: socket root:root → ffsr would require sudo —
   * forbidden (ffsr runs unprivileged, like curl/ping). */
  int ws_uid = detect_ws_owner_uid();
  if (ws_uid > 0) {
    gid_t gid = sudo_gid();
    if (chown(path, ws_uid, gid) != 0) {
      log_err("chown %s → %d:%d: %s", path, ws_uid, (int)gid, strerror(errno));
    } else {
      log_msg("socket chowned → uid %d (WS owner) + group %d",
              ws_uid, (int)gid);
    }
  } else {
    log_err("WS owner not detected — socket root:root (no non-root access)");
  }

  if (listen(fd, 16) != 0) {
    log_err("listen: %s", strerror(errno));
    close(fd);
    return -1;
  }
  log_msg("socket %s (mode %o) ready", path, SOCK_MODE);
  return fd;
}

/* ------------------------------------------------------------- ws utils */

/* Locate the numeric value of the "id" field (doc → offset + length).
 * Returns 0 found, -1 otherwise. This is THE ONLY daemon parsing. */
static int find_id_value(const char *doc, size_t len, size_t *off, size_t *vlen) {
  const char *p = doc, *end = doc + len;
  while (p < end) {
    const char *k = strstr(p, "\"id\"");
    if (!k || k >= end) return -1;
    const char *c = k + 4;                    /* after "id" */
    while (c < end && (*c == ' ' || *c == '\t' || *c == ':')) c++;
    if (c >= end) return -1;
    if (*c != '"') {                          /* numeric value */
      size_t s = (size_t)(c - doc);
      const char *v = c;
      while (v < end && (v[0] >= '0' && v[0] <= '9')) v++;
      if (v == c) { p = k + 4; continue; }    /* not a number: search on */
      *off = s;
      *vlen = (size_t)(v - c);
      return 0;
    }
    p = k + 4;                                /* string value: search on */
  }
  return -1;
}

/* Rewrites "id":X into "id":NV in the middle of doc. Returns the new
 * (allocated) buffer or NULL. */
static char *rewrite_id(const char *doc, size_t len, long new_id) {
  size_t off = 0, vlen = 0;
  if (find_id_value(doc, len, &off, &vlen) != 0) return NULL;
  char idstr[32];
  int n = snprintf(idstr, sizeof(idstr), "%ld", new_id);
  size_t total = off + (size_t)n + (len - (off + vlen)) + 1;
  char *out = malloc(total);
  if (!out) return NULL;
  memcpy(out, doc, off);
  memcpy(out + off, idstr, (size_t)n);
  memcpy(out + off + (size_t)n, doc + off + vlen, len - (off + vlen));
  out[total - 1] = '\0';
  return out;
}

/* ---------------------------------------------------- ws to firefox */

static int ws_send(CURL *curl, const char *data, size_t len) {
  size_t sent = 0;
  CURLcode rc = curl_ws_send(curl, data, len, &sent, 0, CURLWS_TEXT);
  if (rc != CURLE_OK) {
    log_err("curl_ws_send: %s", curl_easy_strerror(rc));
    return -1;
  }
  return (int)sent == (int)len ? 0 : -1;
}

/* Sends a daemon-side command (does not go through the client table). */
static int ws_command(const char *method, const char *params_json) {
  long id = g_next_id++;
  Buf t;
  buf_init(&t);
  buf_printf(&t, "{\"id\":%ld,\"method\":\"%s\",\"params\":", id, method);
  if (params_json) buf_puts(&t, params_json);
  else buf_puts(&t, "{}");
  buf_puts(&t, "}");
  int rc = ws_send(g_curl, t.data ? t.data : "", t.len);
  if (rc == 0) {
    /* the response will come on the WS with this id: we consume it
     * ourselves */
    for (int i = 0; i < MAX_PENDING; i++) {
      if (!pending[i].used) {
        pending[i].used = 1;
        pending[i].fd = -1;            /* response for the daemon */
        pending[i].id_global = id;
        pending[i].id_client = 0;
        break;
      }
    }
  }
  buf_free(&t);
  return rc;
}

/* Waits for a WS response destined to the daemon (fd=-1), timeout ms.
 * Returns the (complete) buffer pointer or NULL. */
static const char *ws_wait_daemon_response(int timeout_ms) {
  /* Short blocking read: read until the response is found. */
  fd_set rfds;
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(g_wsfd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (tv.tv_sec == 0 && tv.tv_usec == 0) {
      tv.tv_sec = 10;
      tv.tv_usec = 0;
    }
    /* partial message already received → give extra time to arrive
     * (fragmented frame) instead of declaring death */
    if (g_wsbuf.len) {
      tv.tv_sec = 10;
      tv.tv_usec = 0;
    }
    int r = select(g_wsfd + 1, &rfds, NULL, NULL, &tv);
    if (r <= 0) return NULL;
    char buf[8192];
    size_t n = sizeof(buf);
    const struct curl_ws_frame *meta = NULL;
    CURLcode rc = curl_ws_recv(g_curl, buf, n, &n, &meta);
    if (rc != CURLE_OK) {
      if (rc == CURLE_AGAIN) continue;
      log_err("curl_ws_recv (wait): %s", curl_easy_strerror(rc));
      return NULL;
    }
    if (n == 0) continue;
    buf_append(&g_wsbuf, buf, n);
    /* message incomplete as long as the frame has remaining bytes —
     * CURLWS_CONT is not enough: the FIRST fragment of a frame is not
     * CONT (bug of the serial recreations, fixed) */
    if (meta && meta->bytesleft > 0) continue;
    /* complete message: daemon response OR a client's (route!) */
    long resp_id = 0;
    int found = json_get(g_wsbuf.data, g_wsbuf.len, "id", NULL, &resp_id) != JSON_NOTFOUND;
    if (found) {
      for (int i = 0; i < MAX_PENDING; i++) {
        if (pending[i].used && pending[i].fd == -1 &&
            pending[i].id_global == resp_id) {
          pending[i].used = 0;
          const char *ret = xstrdup(g_wsbuf.data);
          buf_reset(&g_wsbuf);
          log_msg("daemon response (id %ld) consumed", resp_id);
          return ret;
        }
      }
    }
    /* not the daemon response: a CLIENT response — route it (never lost
     * during internal calls) then continue */
    relay_message(g_wsbuf.data, g_wsbuf.len);
    buf_reset(&g_wsbuf);
  }
}

/* WS connection + session creation (the absolute prerequisite). */
static int ws_connect_firefox(void) {
  g_curl = curl_easy_init();
  if (!g_curl) { log_err("curl_easy_init"); return -1; }

  curl_easy_setopt(g_curl, CURLOPT_URL, WS_URL);
  /* 2L (and not 1L): libcurl does the full HTTP upgrade (GET + Upgrade
   * → 101) during perform, then control returns to the application.
   * With 1L, only the TCP connection is established WITHOUT upgrade →
   * the server never sees a request → curl_ws_send fails. */
  curl_easy_setopt(g_curl, CURLOPT_CONNECT_ONLY, 2L);
  /* no global timeout: the daemon lives in silence (idle persistence) */
  curl_easy_setopt(g_curl, CURLOPT_TIMEOUT, 0L);
  CURLcode rc = curl_easy_perform(g_curl);
  if (rc != CURLE_OK) {
    log_err("connection %s: %s", WS_URL, curl_easy_strerror(rc));
    curl_easy_cleanup(g_curl);
    g_curl = NULL;
    return -1;
  }
  curl_easy_getinfo(g_curl, CURLINFO_ACTIVESOCKET, &g_wsfd);
  set_sock_buffers(g_wsfd);   /* heavy WS payloads must pass through */
  g_ws_alive = 1;   /* from here on: every error path must return the session */
  log_msg("WS connected to %s (fd %d)", WS_URL, g_wsfd);

  /* The only creation: session.new */
  log_msg("session.new sent");
  if (ws_command("session.new", "{\"capabilities\":{}}") != 0) return -1;
  const char *rep = ws_wait_daemon_response(HANDSHAKE_TO);
  if (!rep) { log_err("no session.new response"); return -1; }
  const char *sid = NULL;
  if (json_get(rep, strlen(rep), "sessionId", &sid, NULL) == JSON_STR) {
    log_msg("session created: %.8s…", sid);
  } else if (strstr(rep, "\"error\":\"session not created\"") &&
             strstr(rep, "Maximum number of active sessions")) {
    log_err("zombie session still locked — reboot Firefox");
    log_msg("session.new response: %s", rep);
    free((void *)rep);
    ws_command("session.end", "{}");
    const char *end_rep = ws_wait_daemon_response(HANDSHAKE_TO);
    if (end_rep && strstr(end_rep, "\"type\":\"success\"") == NULL)
      log_msg("session.end response: %s", end_rep);
    free((void *)end_rep);
    return -1;
  } else {
    log_msg("session.new response: %s", rep);
  }
  free((void *)rep);

  /* get-file channel (2026-08-12) : Firefox writes the downloaded blobs
   * here — the CLI reads them, serves them on stdout, then purges them. */
  if (mkdir("/tmp/ffsr", 0777) != 0 && errno != EEXIST) {
    log_msg("warning: cannot mkdir /tmp/ffsr (errno %d)", errno);
  }
  chmod("/tmp/ffsr", 0777);
  if (ws_command("browser.setDownloadBehavior",
                 "{\"downloadBehavior\":{\"type\":\"allowed\","
                 "\"destinationFolder\":\"/tmp/ffsr\"}}") != 0) {
    log_msg("warning: browser.setDownloadBehavior failed");
  } else {
    rep = ws_wait_daemon_response(HANDSHAKE_TO);
    if (rep && strstr(rep, "\"type\":\"success\"") == NULL)
      log_msg("setDownloadBehavior response: %s", rep);
    free((void *)rep);
    log_msg("download behavior: allowed → /tmp/ffsr");
  }
  return 0;
}

/* --------------------------------------------------- relay client→ws */

/* Takes a client's complete frame, rewrites the id, puts it on the WS. */
static void client_to_ws(int slot) {
  Client *c = &clients[slot];
  /* Streaming client (get con): session.subscribe marks the connection
   * so that the daemon keeps it open and relays WS events to it. */
  if (strstr(c->in.data, "\"method\":\"session.subscribe\"")) {
    c->stream = 1;
    log_msg("client #%d: streaming mode (session.subscribe)", slot);
  }
  long id_client = 0;
  if (json_get(c->in.data, c->in.len, "id", NULL, &id_client) == JSON_NOTFOUND) {
    log_msg("client #%d: frame without id, relayed as-is", slot);
  }

  long id_global = g_next_id++;
  char *t = rewrite_id(c->in.data, c->in.len, id_global);
  if (!t) {
    log_err("client #%d: cannot rewrite id (%s)", slot,
            c->in.len > 80 ? c->in.data : "(empty)");
    t = xstrdup("{\"error\":\"id rewrite failed\"}");
  }
  int saved = 0;
  for (int i = 0; i < MAX_PENDING; i++) {
    if (!pending[i].used) {
      pending[i].used = 1;
      pending[i].fd = c->fd;
      pending[i].id_global = id_global;
      pending[i].id_client = id_client;
      saved = 1;
      break;
    }
  }
  if (!saved) {
    log_err("id table full (%d) — frame dropped", MAX_PENDING);
    free(t);
    return;
  }
  int rc = ws_send(g_curl, t, strlen(t));
  free(t);
  if (rc != 0) log_err("client #%d: WS send failed", slot);
}

/* --------------------------------------------------- relay ws→client */

/* Routes a complete WS message to its client (or consumes it if the
 * response is for the daemon). Factored: used by ws_to_clients AND by
 * ws_wait_daemon_response (client responses arriving during an internal
 * wait are never lost). */
static void relay_message(const char *data, size_t len) {
  long id_global = 0;
  JsonVal jv = json_get(data, len, "id", NULL, &id_global);
  if (jv == JSON_NOTFOUND) {
    /* WS event (no id): relay to the streaming clients (get con), or
     * ignore (the historical behaviour — one request/response per
     * connection, events were noise). */
    int relayed = 0;
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (clients[i].fd >= 0 && clients[i].stream) {
        log_msg("TRC event: %zu octets vers fd %d — %.60s", len,
                clients[i].fd, data);
        if (write_all(clients[i].fd, data, len) != 0)
          log_msg("client fd %d: write failed", clients[i].fd);
        clients[i].last_seen = time(NULL);
        relayed = 1;
      }
    }
    if (!relayed)
      log_msg("ws: message without id (event), ignored");
    return;
  }
  for (int i = 0; i < MAX_PENDING; i++) {
    if (pending[i].used && pending[i].id_global == id_global) {
      int fd = pending[i].fd;
      long id_client = pending[i].id_client;
      pending[i].used = 0;
      if (fd < 0) {
        /* response for the daemon: ws_wait_daemon_response is waiting */
        return;
      }
      char *t = rewrite_id(data, len, id_client);
      if (t) {
        size_t tl = strlen(t);
        log_msg("TRC relais: %zu octets vers fd %d — %.80s",
                tl, fd, t);
        if (write_all(fd, t, tl) != 0)
          log_msg("client fd %d: write failed", fd);
        for (int c = 0; c < MAX_CLIENTS; c++)
          if (clients[c].fd == fd) clients[c].last_seen = time(NULL);
        free(t);
      } else {
        /* no id in the response: relayed as-is */
        if (write_all(fd, data, len) != 0)
          log_msg("client fd %d: write failed", fd);
      }
      /* flight 2 convention: one response per connection → close,
       * EXCEPT for streaming clients (get con): the connection stays
       * open and WS events keep flowing to them. */
      for (int c = 0; c < MAX_CLIENTS; c++) {
        if (clients[c].fd == fd && !clients[c].stream) {
          client_close_slot(c);
          break;
        }
      }
      log_msg("response routed to fd %d (id %ld)", fd, id_client);
      return;
    }
  }
  log_msg("ws: unrouted response/event (id %ld), ignored", id_global);
}

static void ws_to_clients(void) {
  char buf[16384];
  const struct curl_ws_frame *meta = NULL;
  for (;;) {
    size_t n = sizeof(buf);
    CURLcode rc = curl_ws_recv(g_curl, buf, n, &n, &meta);
    if (rc == CURLE_AGAIN) return;           /* no more buffered fragments */
    if (rc != CURLE_OK) {
      log_err("curl_ws_recv: %s", curl_easy_strerror(rc));
      return;
    }
    if (n == 0) return;
    if (meta && (meta->flags & CURLWS_PING)) {
      /* answer pong on the fly, relay nothing */
      size_t sent = 0;
      curl_ws_send(g_curl, buf, n, &sent, 0, CURLWS_PONG);
      continue;
    }
    buf_append(&g_wsbuf, buf, n);
    /* message incomplete as long as the frame has remaining bytes —
     * CURLWS_CONT is not enough: the FIRST fragment of a frame is not
     * CONT. Loop on curl_ws_recv to drain ALL fragments that may be
     * buffered internally by libcurl; return only on CURLE_AGAIN. */
    if (meta && meta->bytesleft > 0) continue;
    relay_message(g_wsbuf.data, g_wsbuf.len);
    buf_reset(&g_wsbuf);
  }
}

/* --------------------------------------------------- clean exit */

/* THE pivot of every ffsrd exit: session.end if the WS is alive, then
 * full cleanup. NEVER exit without going through here — otherwise an
 * orphan session = Firefox restart required. */
static void shutdown_daemon(int code) {
  if (g_ws_alive && g_curl) {
    log_msg("shutdown — session.end");
    ws_command("session.end", "{}");
    /* Wait for Firefox to actually process session.end (not just send it).
     * Without this, the session stays locked and the next ffsrd gets
     * "Maximum number of active sessions". */
    const char *rep = ws_wait_daemon_response(10000);
    if (rep && strstr(rep, "\"type\":\"success\"") == NULL)
      log_msg("session.end response: %s", rep);
    free((void *)rep);
    /* WS protocol CLOSE frame: clean closure (code 1000) — without it,
     * Firefox sees an abnormal closure (1006).
     * NB: this is NOT the forbidden ws.close (never WITHOUT session.end). */
    size_t sent = 0;
    curl_ws_send(g_curl, NULL, 0, &sent, 0, CURLWS_CLOSE);
    sleep(10);
    g_ws_alive = 0;
  }
  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i].fd >= 0) close(clients[i].fd);
    buf_free(&clients[i].in);
  }
  if (listen_fd >= 0) close(listen_fd);
  unlink(SOCK_PATH);
  if (window_listen_fd >= 0) close(window_listen_fd);
  unlink(WINDOW_SOCK);
  if (g_curl) curl_easy_cleanup(g_curl);
  g_curl = NULL;
  buf_free(&g_wsbuf);
  curl_global_cleanup();
  log_msg(code == EXIT_OK ? "ffsrd stopped cleanly"
                          : "ffsrd stopped on error (%d)", code);
  exit(code);
}

/* --------------------------------------------------- persistent state */

/* /var/lib/ffsrd/state — the daemon's SURVIVAL MEMORY (never a CLI
 * interface): window hint + tab0-9 → contextId mapping, for the startup
 * reconciliation. Firefox remains the SOURCE OF TRUTH. */
#define MAX_TABS       10
#define STATE_PATH     "/var/lib/ffsrd/state"

static char g_win_hint[64];
static char g_tabs[MAX_TABS][64];
static int  g_nbtabs = 0;

static void state_load(void) {
  g_nbtabs = 0;
  g_win_hint[0] = '\0';
  for (int i = 0; i < MAX_TABS; i++) g_tabs[i][0] = '\0';
  FILE *f = fopen(STATE_PATH, "r");
  if (!f) return;
  char line[160];
  while (fgets(line, sizeof(line), f)) {
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
    char *eq = strchr(line, '=');
    if (!eq) continue;
    char *val = eq + 1;
    if (strncmp(line, "window=", 7) == 0) {
      snprintf(g_win_hint, sizeof(g_win_hint), "%s", val);
    } else if (strncmp(line, "tab", 3) == 0 && isdigit((unsigned char)line[3])
               && line[4] == '=') {
      int idx = line[3] - '0';
      if (idx >= 0 && idx < MAX_TABS) {
        snprintf(g_tabs[idx], sizeof(g_tabs[idx]), "%s", val);
        if (val[0] && idx + 1 > g_nbtabs) g_nbtabs = idx + 1;
      }
    }
  }
  fclose(f);
}

/* atomic write-through: state.tmp then rename (no corrupted file if a
 * crash happens mid-write). Called after every mutation. */
static void state_save(void) {
  char tmp[512];
  snprintf(tmp, sizeof(tmp), "%s.tmp", STATE_PATH);
  FILE *f = fopen(tmp, "w");
  if (!f) { log_err("state: opening %s: %s", tmp, strerror(errno)); return; }
  fprintf(f, "window=%s\n", g_win_hint);
  for (int i = 0; i < MAX_TABS; i++)
    fprintf(f, "tab%d=%s\n", i, g_tabs[i]);
  fprintf(f, "nbtabs=%d\n", g_nbtabs);
  fclose(f);
  if (rename(tmp, STATE_PATH) != 0)
    log_err("state: rename %s: %s", tmp, strerror(errno));
}

/* ------------------------------------------------- daemon-side bidi */

/* Command + response wait with default timeout (the whole daemon mechanism
 * goes through here). Returns the allocated response (to free) or NULL. */
static char *bidi_call_timeout(const char *method, const char *params_json,
                               int timeout_ms);
static char *bidi_call(const char *method, const char *params_json) {
  return bidi_call_timeout(method, params_json, 10000);
}
static char *bidi_call_timeout(const char *method, const char *params_json,
                               int timeout_ms) {
  if (ws_command(method, params_json) != 0) return NULL;
  const char *rep = ws_wait_daemon_response(timeout_ms);
  if (!rep) { log_err("bidi_call %s: no response", method); return NULL; }
  return (char *)rep;   /* already allocated by ws_wait_daemon_response */
}

/* Extracts a top-level string INSIDE "result" (e.g. context,
 * clientWindow). Returns 0 or -1. */
static int get_result_str(const char *doc, const char *key,
                          char *out, size_t outsz) {
  size_t rs = 0, re = 0, vs = 0, ve = 0;
  if (json_value_bounds(doc, strlen(doc), "result", &rs, &re) != 1) return -1;
  if (json_get_str_bounds(doc + rs, re - rs, key, &vs, &ve) != JSON_STR) return -1;
  size_t l = ve - vs < outsz - 1 ? ve - vs : outsz - 1;
  memcpy(out, doc + rs + vs, l);
  out[l] = '\0';
  return 0;
}

/* ----------------------------------- dedicated window (prerequisite #1) */

/* Creates THE visible dedicated window + the 9 tabs (full 0-9 matrix,
 * all about:blank, fixed order). The daemon is the ONLY creator. */
static int dedicated_window_create(void) {
  /* the window (tab 0 is born with it — visible by default) */
  char *rep = bidi_call_timeout("browsingContext.create",
                                "{\"type\":\"window\",\"referenceContext\":null}",
                                10000);
  if (!rep) return -1;
  if (get_result_str(rep, "context", g_tabs[0], sizeof(g_tabs[0])) != 0) {
    log_err("create window: response without context: %s", rep);
    free(rep);
    return -1;
  }
  free(rep);

  /* 9 tabs, ALWAYS inside the dedicated window (referenceContext=tab 0
   * → never in a personal window even if another is active) */
  for (int i = 1; i < MAX_TABS; i++) {
    char params[160];
    snprintf(params, sizeof(params),
             "{\"type\":\"tab\",\"referenceContext\":\"%s\"}", g_tabs[0]);
    rep = bidi_call("browsingContext.create", params);
    if (!rep) return -1;
    if (get_result_str(rep, "context", g_tabs[i], sizeof(g_tabs[i])) != 0) {
      log_err("create tab %d: response without context: %s", i, rep);
      free(rep);
      return -1;
    }
    free(rep);
  }
  g_nbtabs = MAX_TABS;

  /* (the FFSR marker via document.title was removed — decision
   * 2026-08-12: a failed attempt rendered useless once window.sock
   * serves the hash from memory; tabs 0-9 are all for work) */

  /* VISIBILITY CHECK: the dedicated window must be visible and active —
   * browser.getClientWindows (never a remembered id: Firefox rotates
   * them, we look for active=true each time) */
  rep = bidi_call("browser.getClientWindows", NULL);
  if (rep) {
    size_t rs = 0, re = 0, cs = 0, ce = 0;
    if (json_value_bounds(rep, strlen(rep), "result", &rs, &re) == 1
        && json_value_bounds(rep + rs, re - rs, "clientWindows", &cs, &ce) == 1) {
      const char *arr = rep + rs + cs;
      size_t pos = 1, s = 0, e = 0;
      while (json_array_next(arr, ce - cs, &pos, &s, &e) > 0) {
        size_t vs = 0, ve = 0;
        long active = 0;
        if (json_get(arr + s, e - s, "active", NULL, &active) == JSON_NUM
            && active) {
          if (json_get_str_bounds(arr + s, e - s, "clientWindow", &vs, &ve)
              == JSON_STR) {
            size_t l = ve - vs < sizeof(g_win_hint) - 1 ? ve - vs
                                                       : sizeof(g_win_hint) - 1;
            memcpy(g_win_hint, arr + s + vs, l);
            g_win_hint[l] = '\0';
          }
          /* visible state: state=normal (page visible) */
          long state = 0;
          json_get(arr + s, e - s, "state", NULL, &state);
          log_msg("dedicated window visible (active, state=%ld, clientWindow=%s)",
                  state, g_win_hint);
          break;
        }
      }
    }
    free(rep);
  }
  state_save();
  log_msg("dedicated window created: %d about:blank tabs (0=%s)", g_nbtabs,
          g_tabs[0]);
  return 0;
}

/* Startup reconciliation: healthy matrix (10 live tabs in order) →
 * nothing to do; otherwise recreate EVERYTHING (a replaced tab would
 * fall to the end of the internal order and break the CLI's positional
 * mapping — decision: all-or-nothing).
 *
 * OBSERVED BUG 2026-08-12: the getTree right after session.new can
 * fail/answer partially (Firefox transitional state) → we retry before
 * declaring the matrix dead, otherwise we pile up windows at every
 * restart. */
static int dedicated_window_ensure(void) {
  state_load();

  /* Firefox exposes different contextIds on every new BiDi session, so
   * comparing the saved state matrix against live contexts is pointless.
   * The only reliable signal is structural: a window with exactly MAX_TABS
   * tabs is the dedicated window. Try up to 3 times, then create. */
  for (int attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) sleep(10);
    char *rep = bidi_call("browsingContext.getTree", "{\"maxDepth\":0}");
    if (!rep) {
      log_err("reconciliation: getTree without response (attempt %d/3)",
              attempt + 1);
      continue;
    }
    size_t rs = 0, re = 0, cs = 0, ce = 0;
    if (json_value_bounds(rep, strlen(rep), "result", &rs, &re) != 1
        || json_value_bounds(rep + rs, re - rs, "contexts", &cs, &ce) != 1) {
      log_msg("reconciliation: unexpected getTree shape (attempt %d/3)", attempt + 1);
      free(rep);
      continue;
    }
    const char *arr = rep + rs + cs;
    size_t pos = 1, s = 0, e = 0;
    char c2[512][96], w2[512][96];
    int n2 = 0;
    while (n2 < 512 && json_array_next(arr, ce - cs, &pos, &s, &e) > 0) {
      size_t vs = 0, ve = 0;
      if (json_get_str_bounds(arr + s, e - s, "context", &vs, &ve)
              != JSON_STR) continue;
      size_t l = ve - vs < 95 ? ve - vs : 95;
      memcpy(c2[n2], arr + s + vs, l); c2[n2][l] = '\0';
      w2[n2][0] = '\0';
      if (json_get_str_bounds(arr + s, e - s, "clientWindow", &vs, &ve)
              == JSON_STR) {
        l = ve - vs < 95 ? ve - vs : 95;
        memcpy(w2[n2], arr + s + vs, l); w2[n2][l] = '\0';
      }
      n2++;
    }
    for (int i = 0; i < n2; i++) {
      if (!w2[i][0]) continue;
      int dejavu = 0;
      for (int j = 0; j < i; j++)
        if (w2[j][0] && strcmp(w2[j], w2[i]) == 0) dejavu = 1;
      if (dejavu) continue;
      int nb = 0;
      for (int k = 0; k < n2; k++)
        if (w2[k][0] && strcmp(w2[k], w2[i]) == 0) nb++;
      if (nb != MAX_TABS) continue;
      g_nbtabs = 0;
      snprintf(g_win_hint, sizeof(g_win_hint), "%.63s", w2[i]);
      for (int k = 0; k < n2 && g_nbtabs < MAX_TABS; k++) {
        if (w2[k][0] && strcmp(w2[k], w2[i]) == 0) {
          size_t cl = strlen(c2[k]);
          if (cl > 63) cl = 63;
          memcpy(g_tabs[g_nbtabs], c2[k], cl);
          g_tabs[g_nbtabs][cl] = '\0';
          g_nbtabs++;
        }
      }
      state_save();
      log_msg("dedicated window RESUMED (matrix %d/10, window=%s)",
              g_nbtabs, g_win_hint);
      free(rep);
      return 0;
    }
    log_msg("reconciliation: %d contexts, no 10-tab window (attempt %d/3)",
            n2, attempt + 1);
    free(rep);
  }

  log_msg("dedicated window missing or matrix incomplete — creation (nbtabs=%d)",
          g_nbtabs);
  return dedicated_window_create();
}

/* ------------------------------------------- window.sock (FFSR-WINDOW) */

/* Answers a window.sock connection: the clientWindow of the dedicated
 * window — FROM MEMORY (g_win_hint, written at creation or resume,
 * mirrored in the state). ZERO BiDi call: the info is already owned;
 * asking Firefox for a getTree on every connection was fragile
 * (fragments, ~10 s of waiting) and useless.
 * The CLI reads it FIRST in every command (tabs, go, get, …).
 * Response: the hash alone + '\n'. */
static void handle_window_client(int cfd) {
  if (!g_win_hint[0]) {
    log_err("window.sock: no known clientWindow (dedicated window never created?)");
    close(cfd);
    return;
  }
  char out[96];
  int n = snprintf(out, sizeof(out), "%s\n", g_win_hint);
  if (write_all(cfd, out, (size_t)n) != 0) log_msg("window.sock: write failed");
  log_msg("window.sock: dedicated window -> %s", g_win_hint);
  close(cfd);
}

/* keepactive: inject a 1s AudioContext heartbeat per tab every 1s
 * 1000Hz tone, gain 1 — Firefox detects playback, tab stays alive.
 * Each injection lasts 1s and auto-closes. */
static void keepactive_inject(const char *ctx, int idx) {
  (void)idx;
  const char *js =
    "(function() {"
    "  if (window.__keepactive_ctx) return;"
    "  try {"
    "    const ctx = new (window.AudioContext || window.webkitAudioContext)();"
    "    const osc = ctx.createOscillator();"
    "    const gain = ctx.createGain();"
    "    osc.frequency.value = 22000;"
    "    gain.gain.value = 1;"
    "    osc.connect(gain);"
    "    gain.connect(ctx.destination);"
    "    osc.start();"
    "    window.__keepactive_ctx = ctx;"
    "  } catch(e) {}"
    "})()";
  char expression[2048];
  snprintf(expression, sizeof(expression), "%s", js);
  Buf esc;
  buf_init(&esc);
  json_escape(&esc, expression, strlen(expression));
  char params[2048];
  snprintf(params, sizeof(params),
           "{\"expression\":\"%.*s\",\"target\":{\"context\":\"%.63s\"},"
           "\"awaitPromise\":false,\"resultOwnership\":\"none\"}",
           (int)esc.len, esc.data, ctx);
  buf_free(&esc);
  ws_command("script.evaluate", params);
}

/* ---------------------------------------------------------------- main */

int main(int argc, char **argv) {
  (void)argc; (void)argv;

  if (getuid() != 0) {
    log_err("ffsrd must run as root (systemd service)");
    return EXIT_ERR;
  }

  /* file log (built-in 1 MB rotation): the system journal only filters
   * the severe — the daemon log is our reliable source. */
  {
    char dir[256];
    snprintf(dir, sizeof(dir), "%s", LOG_PATH);
    char *slash = strrchr(dir, '/');
    if (slash) { *slash = '\0'; mkdir_p(dir); }
    log_set_file(LOG_PATH);
    log_msg("=== ffsrd starts (pid %d) ===", getpid());
  }

  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    log_err("curl_global_init");
    return EXIT_ERR;
  }
  buf_init(&g_wsbuf);

  for (int i = 0; i < MAX_CLIENTS; i++) {
    clients[i].fd = -1;
    clients[i].stream = 0;
    buf_init(&clients[i].in);
  }
  for (int i = 0; i < MAX_PENDING; i++) pending[i].used = 0;

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  /* the session BEFORE listening: the daemon must be the owner */
  if (ws_connect_firefox() != 0) {
    /* ws_connect_firefox() already logged the specific error (zombie,
     * bridge down, etc.). Just shutdown cleanly. */
    shutdown_daemon(EXIT_ERR);
  }

  /* dedicated window BEFORE listening: reliability prerequisite #1 —
   * the daemon is the ONLY creator (window + 10 about:blank tabs). */
  if (dedicated_window_ensure() != 0) {
    log_err("dedicated window init failed — ffsrd will not start");
    shutdown_daemon(EXIT_ERR);
  }

  listen_fd = socket_unix_create(SOCK_PATH);
  if (listen_fd < 0) shutdown_daemon(EXIT_ERR);

  /* window.sock: the dedicated window hash, read first by the CLI in
   * EVERY command (decision 2026-08-12). */
  window_listen_fd = socket_unix_create(WINDOW_SOCK);
  if (window_listen_fd < 0) shutdown_daemon(EXIT_ERR);

  log_msg("ffsrd ready (max %d clients) — Ctrl+C: session.end then exit",
          MAX_CLIENTS);

  fd_set rfds;
  FD_ZERO(&g_rd);
  FD_SET(listen_fd, &g_rd);
  FD_SET(window_listen_fd, &g_rd);
  g_maxfd = listen_fd > window_listen_fd ? listen_fd : window_listen_fd;
  if (g_wsfd > g_maxfd) g_maxfd = g_wsfd;
  FD_SET(g_wsfd, &g_rd);

  while (!g_stop) {
    rfds = g_rd;
    /* Timeout: at most KEEPACTIVE_S to keep the loop responsive for keepactive.
     * Also allows reaping idle clients (session limit 10 min). */
    struct timeval tv = { KEEPACTIVE_S, 0 };
    if (select(g_maxfd + 1, &rfds, NULL, NULL, &tv) < 0) {
      if (errno == EINTR) continue;
      log_err("select: %s", strerror(errno));
      break;
    }

    /* Session timeout (decision 2026-08-12): no client stays connected
     * doing nothing (streams included) — close after 10 min of silence. */
    time_t now = time(NULL);
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (clients[i].fd >= 0 && now - clients[i].last_seen > 600) {
        log_msg("client #%d: session timeout (10 min), closing", i);
        client_close_slot(i);
      }
    }

    /* keepactive: inject audio heartbeat to prevent Firefox tab suspend */
    if (g_nbtabs > 0 && now - g_keepactive_last > KEEPACTIVE_S) {
      if (g_keepactive_idx < g_nbtabs && g_tabs[g_keepactive_idx][0]) {
        keepactive_inject(g_tabs[g_keepactive_idx], g_keepactive_idx);
        log_msg("keepactive: injected tab %d (%s)",
                g_keepactive_idx, g_tabs[g_keepactive_idx]);
      }
      g_keepactive_idx = (g_keepactive_idx + 1) % MAX_TABS;
      g_keepactive_last = now;
    }

    if (FD_ISSET(g_wsfd, &rfds)) ws_to_clients();

    if (FD_ISSET(window_listen_fd, &rfds)) {
      int cfd = accept(window_listen_fd, NULL, NULL);
      if (cfd >= 0) handle_window_client(cfd);
    }

    if (FD_ISSET(listen_fd, &rfds)) {
      int cfd = accept(listen_fd, NULL, NULL);
      if (cfd >= 0) {
        set_sock_buffers(cfd);   /* heavy responses must pass through */
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
          if (clients[i].fd < 0) { slot = i; break; }
        }
        if (slot < 0) {
          log_err("refused: %d clients already connected (max %d)",
                  MAX_CLIENTS, MAX_CLIENTS);
          close(cfd);
        } else {
          clients[slot].fd = cfd;
          clients[slot].last_seen = time(NULL);
          buf_reset(&clients[slot].in);
          if (cfd > g_maxfd) g_maxfd = cfd;
          FD_SET(cfd, &g_rd);
          log_msg("client #%d connected (fd %d)", slot, cfd);
        }
      }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
      int cfd = clients[i].fd;
      if (cfd < 0 || !FD_ISSET(cfd, &rfds)) continue;

      char tmp[4096];
      ssize_t n = read(cfd, tmp, sizeof(tmp));
      if (n <= 0) {
        client_close_slot(i);
        continue;
      }

      buf_append(&clients[i].in, tmp, (size_t)n);
      clients[i].last_seen = time(NULL);
      /* Flight 2 convention: ONE request per connection → once we have
       * read something and the client stops writing (drain), we relay.
       * Simplification: relay when the read did not fill the COMPLETE
       * buffer (the client finished writing its frame). */
      if ((size_t)n < sizeof(tmp)) {
        client_to_ws(i);
      }
    }
  }

  /* Shutdown: the pivot takes care of session.end + cleanup.
   * Never an explicit ws.close: process death closes the socket. */
  shutdown_daemon(EXIT_OK);
}

/* --------------------------------------------------------- end of main */
