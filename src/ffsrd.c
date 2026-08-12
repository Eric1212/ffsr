/*
 * ffsrd — le daemon exposant le WS de Firefox sur /run/ffsrd/ffsr.sock.
 *
 * Rôle (spec) :
 *   - ouvre le WS vers le pont 9222 et crée la session (au démarrage)
 *   - expose le WS sur un socket Unix local
 *   - multiplexe jusqu'à 128 clients simultanés (réécriture d'ids)
 *   - ne comprend AUCUNE commande : passthrough pur, seul champ lu : "id"
 *   - rend la session avant de mourir (session.end), jamais de ws.close
 *
 * Convention jet 2 : UNE demande par connexion client — le daemon ferme
 * la connexion après avoir routé la réponse (le CLI lit jusqu'à EOF).
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

/* --------------------------------------------------------- constantes */

#define MAX_CLIENTS     128              /* spec : multiplexage 128 max */
#define MAX_PENDING     1024             /* ids en vol (8/clients × 128) */
#define SOCK_PATH       "/run/ffsrd/ffsr.sock"
#define WINDOW_SOCK     "/run/ffsrd/window.sock"   /* hash fenêtre dédiée */
#define SOCK_MODE       0660             /* rw: possesseur + groupe sudo */
#define WS_URL          "ws://127.0.0.1:9222/session"
#define HANDSHAKE_TO    5000             /* ms d'attente réponse démarrage */
#define LOG_PATH        "/var/lib/ffsrd/ffsrd.log"

/* ------------------------------------------------------- table routage */

typedef struct {
  int   fd;          /* -1 = libre */
  Buf   in;          /* tampon de lecture (trames entrantes) */
} Client;

typedef struct {
  int   fd;          /* client destinataire ; -1 = le daemon lui-même */
  long  id_global;   /* l'id substitué par le daemon (porté par le WS) */
  long  id_client;   /* l'id d'origine côté client (rendu à la réponse) */
  int   used;
} Pending;

static Client clients[MAX_CLIENTS];
static Pending pending[MAX_PENDING];
static long     g_next_id = 1000;        /* ids globaux, jamais réutilisés */
static int      listen_fd = -1;          /* ffsr.sock (flux BiDi) */
static int      window_listen_fd = -1;   /* window.sock (hash dédiée) */
static int      g_wsfd = -1;             /* socket actif du WS (select) */
static fd_set   g_rd;                    /* fds surveillés (select) */
static int      g_maxfd = -1;            /* borne haute pour select */

/* Route un message WS complet vers son client (défini plus bas, utilisé
 * par ws_wait_daemon_response AVANT sa définition). */
static void relay_message(const char *data, size_t len);

/* curl / websocket */
static CURL  *g_curl = NULL;
static int    g_ws_alive = 0;            /* la connexion WS est-elle vivante ? */
static Buf    g_wsbuf;                   /* fragments reçus avant traite */

/* Ferme LA connexion client (slot) : close + FD_CLR + recalcule g_maxfd.
 * SEUL point de fermeture client — un close sans FD_CLR laisserait un
 * fd fermé dans g_rd → select EBADF → mort du daemon. */
static void client_close_slot(int slot) {
  int fd = clients[slot].fd;
  if (fd < 0) return;
  close(fd);
  FD_CLR(fd, &g_rd);
  if (fd == g_maxfd) { /* recalculer la borne haute */
    g_maxfd = listen_fd;
    if (g_wsfd > g_maxfd) g_maxfd = g_wsfd;
    for (int i = 0; i < MAX_CLIENTS; i++)
      if (clients[i].fd > g_maxfd) g_maxfd = clients[i].fd;
  }
  clients[slot].fd = -1;
  buf_reset(&clients[slot].in);
  log_msg("client n°%d déconnecté", slot);
}

/* curl / websocket */
static Buf    g_wsbuf;                   /* fragments reçus avant traite */

/* ------------------------------------------------------------- signaux */

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
  (void)sig;
  g_stop = 1;
}

/* ---------------------------------------- détection possesseur du WS */

/* Port 9222 en hexadécimal (/proc/net/tcp affiche le port en hex) */
#define WS_PORT_HEX "2406"

/* Détecte l'UID du possesseur du WS (firefox-bin — le bout serveur de la
 * connexion 9222). Le daemon est déjà connecté au WS AVANT de créer le
 * socket : la connexion existe donc forcément dans /proc/net/tcp, et la
 * colonne uid du côté serveur (port local 9222) EST l'uid de firefox-bin.
 * Retourne l'uid (>0) ou -1. */
static int detect_ws_owner_uid(void) {
  const char *files[] = { "/proc/net/tcp", "/proc/net/tcp6", NULL };
  char line[512];

  for (int f = 0; files[f]; f++) {
    FILE *fp = fopen(files[f], "r");
    if (!fp) continue;
    fgets(line, sizeof(line), fp); /* en-tête */
    while (fgets(line, sizeof(line), fp)) {
      char local[64], rem[64], st[16], a[32], b[32];
      unsigned long retr;
      int uid;
      int n = sscanf(line, "%*d: %63s %63s %15s %31s %31s %lx %d",
                     local, rem, st, a, b, &retr, &uid);
      if (n < 7) continue;
      /* le côté écouteur (0A) OU une connexion établie (01) dont le
       * port LOCAL est 9222 = firefox-bin (le serveur du pont) */
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

/* GID du groupe « tous les humains admin » : sudo (Debian/Ubuntu), sinon
 * wheel (Arch/Slackware), sinon root (défaut raisonnable). */
static gid_t sudo_gid(void) {
  struct group *g = getgrnam("sudo");
  if (g) return g->gr_gid;
  g = getgrnam("wheel");
  if (g) return g->gr_gid;
  return 0;
}

/* --------------------------------------------------------- socket unix */

/* mkdir -p équivalent : crée chaque niveau du chemin (mode 0755),
 * tolère EEXIST. Retourne 0 ou -1. */
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
  /* le daemon crée SON répertoire de socket (nécessaire : /run est un
   * tmpfs, purgé à chaque boot — aucune étape manuelle requise). */
  char dir[512];
  size_t len = strlen(path);
  if (len >= sizeof(dir)) { log_err("chemin socket trop long"); return -1; }
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

  /* Propriété (décision 2026-08-11) : le socket appartient au POSSESSEUR
   * du WS (firefox-bin, avec qui ffsrd dialogue) + groupe sudo (les
   * humains admins). Sans ce chown : socket root:root → ffsr exigerait
   * sudo — interdit (ffsr s'utilise sans privilège, comme curl/ping). */
  int ws_uid = detect_ws_owner_uid();
  if (ws_uid > 0) {
    gid_t gid = sudo_gid();
    if (chown(path, ws_uid, gid) != 0) {
      log_err("chown %s → %d:%d: %s", path, ws_uid, (int)gid, strerror(errno));
    } else {
      log_msg("socket chowné → uid %d (possesseur du WS) + groupe %d", ws_uid, (int)gid);
    }
  } else {
    log_err("possesseur du WS non détecté — socket root:root (accès non-root impossible)");
  }

  if (listen(fd, 16) != 0) {
    log_err("listen: %s", strerror(errno));
    close(fd);
    return -1;
  }
  log_msg("socket %s (mode %o) prêt", path, SOCK_MODE);
  return fd;
}

/* ------------------------------------------------------------ ws utils */

/* Localise la valeur numérique du champ "id" (doc → offset + longueur).
 * Retourne 0 trouvé, -1 sinon. C'est LE SEUL parsing du daemon. */
static int find_id_value(const char *doc, size_t len, size_t *off, size_t *vlen) {
  const char *p = doc, *end = doc + len;
  while (p < end) {
    const char *k = strstr(p, "\"id\"");
    if (!k || k >= end) return -1;
    const char *c = k + 4;                    /* après "id" */
    while (c < end && (*c == ' ' || *c == '\t' || *c == ':')) c++;
    if (c >= end) return -1;
    if (*c != '"') {                          /* valeur numérique */
      size_t s = (size_t)(c - doc);
      const char *v = c;
      while (v < end && (v[0] >= '0' && v[0] <= '9')) v++;
      if (v == c) { p = k + 4; continue; }    /* pas un nombre : chercher à côté */
      *off = s;
      *vlen = (size_t)(v - c);
      return 0;
    }
    p = k + 4;                                /* valeur string : chercher ensuite */
  }
  return -1;
}

/* Réécrit "id":X en "id":NV au cœur de doc. Retourne le nouveau buffer
 * (alloué) ou NULL. */
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

/* ------------------------------------------------- ws vers firefox */

static int ws_send(CURL *curl, const char *data, size_t len) {
  size_t sent = 0;
  CURLcode rc = curl_ws_send(curl, data, len, &sent, 0, CURLWS_TEXT);
  if (rc != CURLE_OK) {
    log_err("curl_ws_send: %s", curl_easy_strerror(rc));
    return -1;
  }
  return (int)sent == (int)len ? 0 : -1;
}

/* Envoie une commande côté daemon (ne passe pas par la table client). */
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
    /* la réponse viendra sur le WS avec cet id : on la consomme nous-mêmes */
    for (int i = 0; i < MAX_PENDING; i++) {
      if (!pending[i].used) {
        pending[i].used = 1;
        pending[i].fd = -1;            /* réponse pour le daemon */
        pending[i].id_global = id;
        pending[i].id_client = 0;
        break;
      }
    }
  }
  buf_free(&t);
  return rc;
}

/* Attend une réponse du WS destinée au daemon (fd=-1), timeout ms.
 * Retourne le pointeur du buffer (complet) ou NULL. */
static const char *ws_wait_daemon_response(int timeout_ms) {
  (void)timeout_ms;
  /* Lecture blocante courte : on lit jusqu'à trouver la réponse. */
  struct timeval tv = { 1, 0 };
  fd_set rfds;
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(g_wsfd, &rfds);
    /* message partiel déjà reçu → on laisse le temps à la suite
     * d'arriver (trame fragmentée) au lieu de déclarer la mort */
    tv.tv_sec = g_wsbuf.len ? 10 : 1;
    tv.tv_usec = 0;
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
    /* message incomplet tant que la trame a des octets restants —
     * CURLWS_CONT ne suffit pas : le PREMIER fragment d'une trame
     * n'est pas CONT (bug des recréations en série, résolu) */
    if (meta && meta->bytesleft > 0) continue;
    /* message complet : réponse du daemon OU d'un client (route !) */
    long resp_id = 0;
    int found = json_get(g_wsbuf.data, g_wsbuf.len, "id", NULL, &resp_id) != JSON_NOTFOUND;
    if (found) {
      for (int i = 0; i < MAX_PENDING; i++) {
        if (pending[i].used && pending[i].fd == -1 &&
            pending[i].id_global == resp_id) {
          pending[i].used = 0;
          const char *ret = xstrdup(g_wsbuf.data);
          buf_reset(&g_wsbuf);
          log_msg("réponse daemon (id %ld) consommée", resp_id);
          return ret;
        }
      }
    }
    /* pas la réponse du daemon : réponse d'un CLIENT — on la route
     * (jamais perdue pendant les appels internes) puis on continue */
    relay_message(g_wsbuf.data, g_wsbuf.len);
    buf_reset(&g_wsbuf);
  }
}

/* Connexion WS + création de session (le préalable absolu). */
static int ws_connect_firefox(void) {
  g_curl = curl_easy_init();
  if (!g_curl) { log_err("curl_easy_init"); return -1; }

  curl_easy_setopt(g_curl, CURLOPT_URL, WS_URL);
  /* 2L (et non 1L) : libcurl fait l'upgrade HTTP complet (GET + Upgrade
   * → 101) pendant perform, puis le contrôle revient à l'application.
   * Avec 1L, la connexion TCP seule s'établit SANS upgrade → le serveur
   * ne voit jamais de requête → curl_ws_send échoue. */
  curl_easy_setopt(g_curl, CURLOPT_CONNECT_ONLY, 2L);
  /* pas de timeout global : le daemon vit en silence (persistance idle) */
  curl_easy_setopt(g_curl, CURLOPT_TIMEOUT, 0L);
  CURLcode rc = curl_easy_perform(g_curl);
  if (rc != CURLE_OK) {
    log_err("connexion %s: %s", WS_URL, curl_easy_strerror(rc));
    curl_easy_cleanup(g_curl);
    g_curl = NULL;
    return -1;
  }
  curl_easy_getinfo(g_curl, CURLINFO_ACTIVESOCKET, &g_wsfd);
  g_ws_alive = 1;   /* dès ici : tout chemin d'erreur doit rendre la session */
  log_msg("WS connecté à %s (fd %d)", WS_URL, g_wsfd);

  /* Sonde : session.status — jamais créatrice */
  if (ws_command("session.status", "{}") != 0) return -1;
  const char *rep = ws_wait_daemon_response(HANDSHAKE_TO);
  if (!rep) { log_err("pas de réponse session.status"); return -1; }
  bool ready = strstr(rep, "\"ready\":true") != NULL;
  log_msg("session.status → ready:%s", ready ? "true" : "FALSE");
  if (!ready) {
    /* session existante (zombie ou autre) : on la laisse, pas de création.
     * Les clients verront les réponses d'erreur de Firefox, honnêtement. */
    log_msg("session déjà active — ffsrd relaie sans créer (pont occupé)");
    free((void *)rep);
    return 0;
  }
  free((void *)rep);

  /* La seule création : session.new */
  if (ws_command("session.new", "{\"capabilities\":{}}") != 0) return -1;
  rep = ws_wait_daemon_response(HANDSHAKE_TO);
  if (rep) {
    const char *sid = NULL;
    if (json_get(rep, strlen(rep), "sessionId", &sid, NULL) == JSON_STR) {
      log_msg("session créée : %.8s…", sid);
    } else {
      log_msg("session.new réponse: %s", rep);
    }
    free((void *)rep);
  } else {
    log_err("pas de réponse session.new");
    return -1;
  }
  return 0;
}

/* --------------------------------------------------- relais client→ws */

/* Prend la trame complète d'un client, réécrit l'id, la pose sur le WS. */
static void client_to_ws(int slot) {
  Client *c = &clients[slot];
  long id_client = 0;
  if (json_get(c->in.data, c->in.len, "id", NULL, &id_client) == JSON_NOTFOUND) {
    log_msg("client n°%d : trame sans id, relayée telle quelle", slot);
  }

  long id_global = g_next_id++;
  char *t = rewrite_id(c->in.data, c->in.len, id_global);
  if (!t) {
    log_err("client n°%d : impossible de réécrire l'id (%s)", slot,
            c->in.len > 80 ? c->in.data : "(vide)");
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
    log_err("table d'ids pleine (%d) — trame jetée", MAX_PENDING);
    free(t);
    return;
  }
  int rc = ws_send(g_curl, t, strlen(t));
  free(t);
  if (rc != 0) log_err("client n°%d : envoi WS échoué", slot);
}

/* --------------------------------------------------- relais ws→client */

/* Route un message WS complet vers son client (ou le consomme si la
 * réponse est pour le daemon). Factorisé : utilisé par ws_to_clients ET
 * par ws_wait_daemon_response (les réponses clients arrivées pendant une
 * attente interne ne sont jamais perdues). */
static void relay_message(const char *data, size_t len) {
  long id_global = 0;
  JsonVal jv = json_get(data, len, "id", NULL, &id_global);
  if (jv == JSON_NOTFOUND) {
    log_msg("ws: message sans id (événement), ignoré");
    return;
  }
  for (int i = 0; i < MAX_PENDING; i++) {
    if (pending[i].used && pending[i].id_global == id_global) {
      int fd = pending[i].fd;
      long id_client = pending[i].id_client;
      pending[i].used = 0;
      if (fd < 0) {
        /* réponse pour le daemon : ws_wait_daemon_response l'attend */
        return;
      }
      char *t = rewrite_id(data, len, id_client);
      if (t) {
        size_t tl = strlen(t);
        ssize_t w = write(fd, t, tl);
        if (w != (ssize_t)tl) log_msg("client fd %d: écriture partielle", fd);
        free(t);
      } else {
        /* pas d'id dans la réponse : relayée telle quelle */
        ssize_t w = write(fd, data, len);
        if (w != (ssize_t)len) log_msg("client fd %d: écriture partielle", fd);
      }
      /* convention jet 2 : une réponse par connexion → on ferme */
      for (int c = 0; c < MAX_CLIENTS; c++) {
        if (clients[c].fd == fd) { client_close_slot(c); break; }
      }
      log_msg("réponse routée vers fd %d (id %ld)", fd, id_client);
      return;
    }
  }
  log_msg("ws: réponse/programme non routé (id %ld), ignoré", id_global);
}

static void ws_to_clients(void) {
  char buf[16384];
  size_t n = sizeof(buf);
  const struct curl_ws_frame *meta = NULL;
  CURLcode rc = curl_ws_recv(g_curl, buf, n, &n, &meta);
  if (rc == CURLE_AGAIN) return;
  if (rc != CURLE_OK) {
    log_err("curl_ws_recv: %s", curl_easy_strerror(rc));
    return;
  }
  if (n == 0) return;

  if (meta && (meta->flags & CURLWS_PING)) {
    /* répondre pong à la volée, ne rien relayer */
    size_t sent = 0;
    curl_ws_send(g_curl, buf, n, &sent, 0, CURLWS_PONG);
    return;
  }

  buf_append(&g_wsbuf, buf, n);
  /* message incomplet tant que la trame a des octets restants —
   * CURLWS_CONT ne suffit pas : le PREMIER fragment d'une trame
   * n'est pas CONT (bug des recréations en série, résolu) */
  if (meta && meta->bytesleft > 0) return;

  relay_message(g_wsbuf.data, g_wsbuf.len);
  buf_reset(&g_wsbuf);
}

/* --------------------------------------------------- sortie propre */

/* LE pivot de toute sortie de ffsrd : session.end si le WS est vivant,
 * puis libération complète. JAMAIS de sortie sans passer ici — sinon
 * session orpheline = redémarrage Firefox obligatoire. */
static void shutdown_daemon(int code) {
  if (g_ws_alive && g_curl) {
    log_msg("arrêt — session.end");
    ws_command("session.end", "{}");
    /* laisse partir la trame avant de mourir (write synchrone, mais on
     * attend un court instant pour que Firefox la traite) */
    struct timeval tv = { 0, 300000 };
    select(0, NULL, NULL, NULL, &tv);
    /* frame CLOSE du protocole WS : fermeture propre (code 1000) —
     * sans elle, Firefox voit une fermeture anormale (1006).
     * NB : ce n'est PAS le ws.close interdit (jamais SANS session.end). */
    size_t sent = 0;
    curl_ws_send(g_curl, NULL, 0, &sent, 0, CURLWS_CLOSE);
    usleep(50000);
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
  log_msg(code == EXIT_OK ? "ffsrd arrêté proprement"
                          : "ffsrd arrêté sur erreur (%d)", code);
  exit(code);
}

/* --------------------------------------------------- état persistant */

/* /var/lib/ffsrd/state — MÉMOIRE DE SURVIE du daemon (jamais une
 * interface CLI) : hint fenêtre + mapping tab0-9 → contextId, pour la
 * réconciliation au démarrage. Firefox reste la SOURCE DE VÉRITÉ. */
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

/* write-through atomique : state.tmp puis rename (pas de fichier corrompu
 * si crash en plein écriture). Appelée après chaque mutation. */
static void state_save(void) {
  char tmp[512];
  snprintf(tmp, sizeof(tmp), "%s.tmp", STATE_PATH);
  FILE *f = fopen(tmp, "w");
  if (!f) { log_err("state: ouverture %s: %s", tmp, strerror(errno)); return; }
  fprintf(f, "window=%s\n", g_win_hint);
  for (int i = 0; i < MAX_TABS; i++)
    fprintf(f, "tab%d=%s\n", i, g_tabs[i]);
  fprintf(f, "nbtabs=%d\n", g_nbtabs);
  fclose(f);
  if (rename(tmp, STATE_PATH) != 0)
    log_err("state: rename %s: %s", tmp, strerror(errno));
}

/* ------------------------------------------------- bidi côté daemon */

/* Commande + attente de la réponse (toute la mécanique daemon passe ici).
 * Retourne la réponse allouée (à free) ou NULL. */
static char *bidi_call(const char *method, const char *params_json) {
  if (ws_command(method, params_json) != 0) return NULL;
  const char *rep = ws_wait_daemon_response(5000);
  if (!rep) { log_err("bidi_call %s: pas de réponse", method); return NULL; }
  return (char *)rep;   /* déjà alloué par ws_wait_daemon_response */
}

/* Extrait une string de premier niveau DANS "result" (ex. context,
 * clientWindow). Retourne 0 ou -1. */
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

/* Liste les contextIds de premier niveau du getTree (max max items). */
static int get_context_list(const char *doc, char list[][64], int max) {
  size_t rs = 0, re = 0, cs = 0, ce = 0;
  if (json_value_bounds(doc, strlen(doc), "result", &rs, &re) != 1) return 0;
  if (json_value_bounds(doc + rs, re - rs, "contexts", &cs, &ce) != 1) return 0;
  const char *arr = doc + rs + cs;
  size_t alen = ce - cs;
  size_t pos = 1, s = 0, e = 0;
  int n = 0;
  while (n < max && json_array_next(arr, alen, &pos, &s, &e) > 0) {
    size_t vs = 0, ve = 0;
    if (json_get_str_bounds(arr + s, e - s, "context", &vs, &ve) == JSON_STR) {
      size_t l = ve - vs < 63 ? ve - vs : 63;
      memcpy(list[n], arr + s + vs, l);
      list[n][l] = '\0';
      n++;
    }
  }
  return n;
}

/* ----------------------------------- fenêtre dédiée (prérequis n°1) */

/* Crée LA fenêtre dédiée visible + les 9 onglets (matrice pleine 0-9,
 * tous about:blank, ordre figé). Le daemon est le SEUL créateur. */
static int dedicated_window_create(void) {
  /* la fenêtre (l'onglet 0 naît avec elle — visible par défaut) */
  char *rep = bidi_call("browsingContext.create",
                        "{\"type\":\"window\",\"referenceContext\":null}");
  if (!rep) return -1;
  if (get_result_str(rep, "context", g_tabs[0], sizeof(g_tabs[0])) != 0) {
    log_err("create window: réponse sans context: %s", rep);
    free(rep);
    return -1;
  }
  free(rep);

  /* 9 onglets, toujours DANS la fenêtre dédiée (referenceContext=onglet 0
   * → jamais dans une fenêtre personnelle même si une autre est active) */
  for (int i = 1; i < MAX_TABS; i++) {
    char params[160];
    snprintf(params, sizeof(params),
             "{\"type\":\"tab\",\"referenceContext\":\"%s\"}", g_tabs[0]);
    rep = bidi_call("browsingContext.create", params);
    if (!rep) return -1;
    if (get_result_str(rep, "context", g_tabs[i], sizeof(g_tabs[i])) != 0) {
      log_err("create tab %d: réponse sans context: %s", i, rep);
      free(rep);
      return -1;
    }
    free(rep);
  }
  g_nbtabs = MAX_TABS;

  /* MARQUEUR D'IDENTITÉ (décision 2026-08-12) : la fenêtre dédiée est
   * reconnaissable par le titre fixe "FFSR" sur son onglet 0 — le CLI
   * la cible par ce marqueur, JAMAIS par active=true (la fenêtre active
   * peut être une fenêtre personnelle). */
  {
    char params[192];
    snprintf(params, sizeof(params),
             "{\"expression\":\"document.title='FFSR'\","
             "\"target\":{\"context\":\"%s\"},"
             "\"awaitPromise\":false,\"resultOwnership\":\"none\"}",
             g_tabs[0]);
    char *mrep = bidi_call("script.evaluate", params);
    if (!mrep) {
      log_err("pose marqueur FFSR: pas de réponse");
    } else {
      free(mrep);
      log_msg("marqueur FFSR posé sur l'onglet 0");
    }
  }

  /* VÉRIFICATION DE VISIBILITÉ : la fenêtre dédiée doit être visible et
   * active — browser.getClientWindows (jamais un ID mémorisé : Firefox
   * les rotate, on cherche active=true à chaque fois) */
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
          /* état visible : state=normal (page visible) */
          long state = 0;
          json_get(arr + s, e - s, "state", NULL, &state);
          log_msg("fenêtre dédiée visible (active, state=%ld, clientWindow=%s)",
                  state, g_win_hint);
          break;
        }
      }
    }
    free(rep);
  }
  state_save();
  log_msg("fenêtre dédiée créée : %d onglets about:blank (0=%s)", g_nbtabs,
          g_tabs[0]);
  return 0;
}

/* Réconciliation au démarrage : matrice saine (10 onglets vivants dans
 * l'ordre) → rien à faire ; sinon TOUT recréer (un onglet remplacé
 * tomberait en fin d'ordre interne et casserait le mapping par position
 * du CLI — décision : tout-ou-rien).
 *
 * BUG OBSERVÉ 2026-08-12 : le getTree juste après session.new peut
 * échouer/répondre partiellement (état transitoire Firefox) → on
 * réessaie avant de déclarer la matrice morte, sinon on empile des
 * fenêtres à chaque redémarrage. */
static int dedicated_window_ensure(void) {
  state_load();

  int ok = 0;
  int nalive = 0;
  for (int attempt = 0; attempt < 3 && !ok; attempt++) {
    if (attempt > 0) usleep(500000);   /* 500 ms entre les essais */
    char *rep = bidi_call("browsingContext.getTree", "{\"maxDepth\":0}");
    if (!rep) {
      log_err("réconciliation: getTree sans réponse (essai %d/3)", attempt + 1);
      continue;
    }
    char alive[64][64];
    nalive = get_context_list(rep, alive, 64);
    if (nalive < 10)
      log_msg("réconciliation: %d contextes visibles (essai %d/3) — réponse: %.*s",
              nalive, attempt + 1, (int)(strlen(rep) > 300 ? 300 : strlen(rep)),
              rep);
    free(rep);

    ok = g_nbtabs == MAX_TABS && g_tabs[0][0];
    for (int i = 0; ok && i < MAX_TABS; i++) {
      int found = 0;
      for (int j = 0; j < nalive; j++)
        if (strcmp(g_tabs[i], alive[j]) == 0) { found = 1; break; }
      if (!found) ok = 0;
    }
    if (!ok && nalive >= 10) {
      /* des contextes existent mais pas ceux du state : la fenêtre a pu
       * être fermée manuellement — recréer (comportement prévu) */
      log_msg("réconciliation: %d contextes vivants ≠ matrice du state",
              nalive);
    }
  }

  if (ok) {
    log_msg("fenêtre dédiée présente (matrice %d/10 saine, window=%s)",
            g_nbtabs, g_win_hint);
    /* re-pose le marqueur (idempotent) : l'onglet 0 a pu être navigué */
    char params[192];
    snprintf(params, sizeof(params),
             "{\"expression\":\"document.title='FFSR'\","
             "\"target\":{\"context\":\"%s\"},"
             "\"awaitPromise\":false,\"resultOwnership\":\"none\"}",
             g_tabs[0]);
    char *mrep = bidi_call("script.evaluate", params);
    if (!mrep) log_err("re-pose marqueur FFSR: pas de réponse");
    else free(mrep);
    return 0;
  }

  /* NIVEAU 2 — décision 2026-08-12 : le daemon ne ferme JAMAIS les
   * fenêtres ; quand la matrice du state est introuvable, il REPREND
   * une fenêtre dédiée existante (marquée FFSR) au lieu d'en créer une
   * nouvelle → pas de cascade de fenêtres à chaque redémarrage. */
  {
    /* re-getTree pour repartir sur des données fraîches */
    char *rep = bidi_call("browsingContext.getTree", "{\"maxDepth\":0}");
    if (rep) {
      size_t rs = 0, re = 0, cs = 0, ce = 0;
      if (json_value_bounds(rep, strlen(rep), "result", &rs, &re) == 1
          && json_value_bounds(rep + rs, re - rs, "contexts", &cs, &ce) == 1) {
        const char *arr = rep + rs + cs;
        size_t pos = 1, s = 0, e = 0;
        /* collecte : chaque (contextId, clientWindow) avec URL */
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
        /* pour chaque clientWindow distinct : le 1er onglet est-il
         * marqué FFSR ? si oui, la fenêtre est dédiée → reprendre */
        for (int i = 0; i < n2; i++) {
          if (!w2[i][0]) continue;
          int dejavu = 0;
          for (int j = 0; j < i; j++)
            if (w2[j][0] && strcmp(w2[j], w2[i]) == 0) dejavu = 1;
          if (dejavu) continue;
          /* tester le marqueur sur ce 1er onglet */
          char params[512];
          snprintf(params, sizeof(params),
                   "{\"expression\":\"document.title\","
                   "\"target\":{\"context\":\"%s\"},"
                   "\"awaitPromise\":false,\"resultOwnership\":\"none\"}",
                   c2[i]);
          char *mrep = bidi_call("script.evaluate", params);
          if (!mrep) continue;
          int marked = strstr(mrep, "\"FFSR\"") != NULL;
          free(mrep);
          if (!marked) continue;
          /* fenêtre dédiée trouvée : l'adopter (state mis à jour) */
          g_nbtabs = 0;
          snprintf(g_win_hint, sizeof(g_win_hint), "%s", w2[i]);
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
          log_msg("fenêtre dédiée REPRISE (matrice %d/10, window=%s)",
                  g_nbtabs, g_win_hint);
          return 0;
        }
      }
      free(rep);
    }
  }

  log_msg("fenêtre dédiée absente ou matrice incomplète — création (nbtabs=%d)",
          g_nbtabs);
  return dedicated_window_create();
}

/* ------------------------------------------- window.sock (FFSR-WINDOW) */

/* Répond à une connexion window.sock : le clientWindow ACTUEL de la
 * fenêtre dédiée (résolu au moment présent via getTree + matching du
 * state — jamais un hint mémorisé : les IDs de fenêtres rotatent).
 * Le CLI le lit EN PREMIER dans chaque commande (tabs, go, get, …).
 * Réponse : le hash seul + '\n' ; rien si la matrice est morte. */
/* Répond à une connexion window.sock : le clientWindow de la fenêtre
 * dédiée — DEPUIS LA MÉMOIRE (g_win_hint, écrit à la création ou à la
 * reprise, doublé dans le state). ZÉRO appel BiDi : l'info est déjà
 * possédée ; demander un getTree à Firefox à chaque connexion était
 * fragile (fragments, ~10 s d'attente) et inutile.
 * Le CLI le lit EN PREMIER dans chaque commande (tabs, go, get, …).
 * Réponse : le hash seul + '\n'. */
static void handle_window_client(int cfd) {
  if (!g_win_hint[0]) {
    log_err("window.sock: aucun clientWindow connu (fenêtre dédiée jamais créée ?)");
    close(cfd);
    return;
  }
  char out[96];
  int n = snprintf(out, sizeof(out), "%s\n", g_win_hint);
  ssize_t w = write(cfd, out, (size_t)n);
  if (w != n) log_msg("window.sock: écriture partielle");
  log_msg("window.sock: fenêtre dédiée -> %s", g_win_hint);
  close(cfd);
}

/* --------------------------------------------------------------- main */

int main(int argc, char **argv) {
  (void)argc; (void)argv;

  if (getuid() != 0) {
    log_err("ffsrd doit tourner root (service systemd)");
    return EXIT_ERR;
  }

  /* log fichier (rotation 1 Mo intégrée) : le journal système ne filtre
   * que le grave — le log du daemon est notre source fiable. */
  {
    char dir[256];
    snprintf(dir, sizeof(dir), "%s", LOG_PATH);
    char *slash = strrchr(dir, '/');
    if (slash) { *slash = '\0'; mkdir_p(dir); }
    log_set_file(LOG_PATH);
    log_msg("=== ffsrd démarre (pid %d) ===", getpid());
  }

  if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
    log_err("curl_global_init");
    return EXIT_ERR;
  }
  buf_init(&g_wsbuf);

  for (int i = 0; i < MAX_CLIENTS; i++) {
    clients[i].fd = -1;
    buf_init(&clients[i].in);
  }
  for (int i = 0; i < MAX_PENDING; i++) pending[i].used = 0;

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  /* la session AVANT d'écouter : le daemon doit être possesseur */
  if (ws_connect_firefox() != 0) {
    log_err("échec de la liaison WS — ffsrd ne démarre pas (pont down ?)");
    /* Si le WS est connecté (g_ws_alive), session.end sera tenté :
     * pas de session créée sans être rendue. */
    shutdown_daemon(EXIT_ERR);
  }

  /* fenêtre dédiée AVANT d'écouter : le prérequis n°1 de fiabilité —
   * le daemon est le SEUL créateur (window + 10 onglets about:blank). */
  if (dedicated_window_ensure() != 0) {
    log_err("échec de l'init de la fenêtre dédiée — ffsrd ne démarre pas");
    shutdown_daemon(EXIT_ERR);
  }

  listen_fd = socket_unix_create(SOCK_PATH);
  if (listen_fd < 0) shutdown_daemon(EXIT_ERR);

  /* window.sock : le hash de la fenêtre dédiée, lu en premier par le
   * CLI dans CHAQUE commande (décision 2026-08-12). */
  window_listen_fd = socket_unix_create(WINDOW_SOCK);
  if (window_listen_fd < 0) shutdown_daemon(EXIT_ERR);

  log_msg("ffsrd prêt (max %d clients) — Ctrl+C: session.end puis sortie",
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
    if (select(g_maxfd + 1, &rfds, NULL, NULL, NULL) < 0) {
      if (errno == EINTR) continue;
      log_err("select: %s", strerror(errno));
      break;
    }

    if (FD_ISSET(g_wsfd, &rfds)) ws_to_clients();

    if (FD_ISSET(window_listen_fd, &rfds)) {
      int cfd = accept(window_listen_fd, NULL, NULL);
      if (cfd >= 0) handle_window_client(cfd);
    }

    if (FD_ISSET(listen_fd, &rfds)) {
      int cfd = accept(listen_fd, NULL, NULL);
      if (cfd >= 0) {
        int slot = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
          if (clients[i].fd < 0) { slot = i; break; }
        }
        if (slot < 0) {
          log_err("refus : %d clients déjà connectés (max %d)",
                  MAX_CLIENTS, MAX_CLIENTS);
          close(cfd);
        } else {
          clients[slot].fd = cfd;
          buf_reset(&clients[slot].in);
          if (cfd > g_maxfd) g_maxfd = cfd;
          FD_SET(cfd, &g_rd);
          log_msg("client n°%d connecté (fd %d)", slot, cfd);
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
      /* Convention jet 2 : UNE demande par connexion → dès qu'on a lu
       * quelque chose et que le client n'écrit plus (drain), on relaie.
       * Simplification : on relaie quand le read n'a pas rempli le
       * tampon COMPLET (le client a fini d'écrire sa trame). */
      if ((size_t)n < sizeof(tmp)) {
        client_to_ws(i);
      }
    }
  }

  /* Arrêt : le pivot s'occupe de session.end + libération.
   * Jamais de ws.close explicite : la mort du processus ferme le socket. */
  shutdown_daemon(EXIT_OK);
}

/* --------------------------------------------------------- fin main fin */