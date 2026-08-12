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
static int      listen_fd = -1;
static int      g_wsfd = -1;             /* socket actif du WS (select) */
static fd_set   g_rd;                    /* fds surveillés (select) */
static int      g_maxfd = -1;            /* borne haute pour select */

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
    if (meta && (meta->flags & CURLWS_CONT)) continue; /* fragments : incomplet */
    /* message complet : le consommer côté daemon */
    long resp_id = 0;
    int found = json_get(g_wsbuf.data, g_wsbuf.len, "id", NULL, &resp_id) != JSON_NOTFOUND;
    if (found) {
      for (int i = 0; i < MAX_PENDING; i++) {
        if (pending[i].used && pending[i].fd == -1 &&
            pending[i].id_global == resp_id) {
          pending[i].used = 0;
          const char *ret = xstrdup(g_wsbuf.data);
          buf_reset(&g_wsbuf);
          return ret;
        }
      }
    }
    /* pas notre réponse : garder tel quel et continuer d'attendre */
    buf_reset(&g_wsbuf);
    log_msg("ws: réponse/programme non routé (id %ld), ignoré", resp_id);
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
  if (meta && (meta->flags & CURLWS_CONT)) return;  /* fragments : pas complet */
  if (g_wsbuf.len == 0) return;

  /* message WS complet : routage par id */
  long id_global = 0;
  JsonVal jv = json_get(g_wsbuf.data, g_wsbuf.len, "id", NULL, &id_global);
  if (jv == JSON_NOTFOUND) {
    log_msg("ws: message sans id (événement), ignoré");
    buf_reset(&g_wsbuf);
    return;
  }

  for (int i = 0; i < MAX_PENDING; i++) {
    if (pending[i].used && pending[i].id_global == id_global) {
      int fd = pending[i].fd;
      long id_client = pending[i].id_client;
      pending[i].used = 0;
      if (fd < 0) {
        /* réponse pour le daemon (session.new/status) : normalement
         * consommée par ws_wait_daemon_response ; ici : log léger */
        log_msg("ws: réponse daemon (id %ld) hors attente, ignorée", id_global);
      } else {
        char *t = rewrite_id(g_wsbuf.data, g_wsbuf.len, id_client);
        if (t) {
          size_t tl = strlen(t);
          ssize_t w = write(fd, t, tl);
          if (w != (ssize_t)tl) log_msg("client fd %d: écriture partielle", fd);
          free(t);
        } else {
          /* pas d'id dans la réponse : relayée telle quelle */
          ssize_t w = write(fd, g_wsbuf.data, g_wsbuf.len);
          if (w != (ssize_t)g_wsbuf.len) log_msg("client fd %d: écriture partielle", fd);
        }
        /* convention jet 2 : une réponse par connexion → on ferme */
        for (int c = 0; c < MAX_CLIENTS; c++) {
          if (clients[c].fd == fd) { client_close_slot(c); break; }
        }
        log_msg("réponse routée vers fd %d (id %ld)", fd, id_client);
      }
      break;
    }
  }
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
  if (g_curl) curl_easy_cleanup(g_curl);
  g_curl = NULL;
  buf_free(&g_wsbuf);
  curl_global_cleanup();
  log_msg(code == EXIT_OK ? "ffsrd arrêté proprement"
                          : "ffsrd arrêté sur erreur (%d)", code);
  exit(code);
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

  listen_fd = socket_unix_create(SOCK_PATH);
  if (listen_fd < 0) shutdown_daemon(EXIT_ERR);

  log_msg("ffsrd prêt (max %d clients) — Ctrl+C: session.end puis sortie",
          MAX_CLIENTS);

  fd_set rfds;
  FD_ZERO(&g_rd);
  FD_SET(listen_fd, &g_rd);
  g_maxfd = listen_fd;
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