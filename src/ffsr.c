/*
 * ffsr — le CLI qui parle BiDi à Firefox À TRAVERS le tunnel ffsrd.
 *
 * ffsr ne connaît pas le pont : il se connecte à /run/ffsrd/ffsr.sock,
 * envoie sa trame JSON BiDi telle quelle (comme s'il était au 9222),
 * ffsrd réécrit l'id et la relate à Firefox ; la réponse revient ici,
 * l'id d'origine est rendu, et ffsr l'imprime telle quelle sur stdout.
 *
 * Ce premier jet : connexion socket, envoi brut + attente réponse,
 * et le squelette de dispatch des commandes (ffsr d = systemctl).
 */

#include "common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCK_PATH       "/run/ffsrd/ffsr.sock"
#define WINDOW_SOCK     "/run/ffsrd/window.sock"

/* --------------------------------------------------- socket vers tunnel */

static int tunnel_connect(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SOCK_PATH);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
  }
  return fd;
}

/* ---------------------------------------------------- trame + réponse */

/* read jusqu'à EOF avec plafond de temps : le CLI ne hang JAMAIS,
 * même si le daemon reste muet (décision 2026-08-12). */
static int read_until_eof(int fd, Buf *out, int timeout_s) {
  struct timeval tv;
  fd_set rfds;
  char tmp[8192];
  for (;;) {
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    tv.tv_sec = timeout_s;
    tv.tv_usec = 0;
    int r = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (r <= 0) return -1;          /* timeout : on rend la main */
    ssize_t n = read(fd, tmp, sizeof(tmp));
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (n == 0) return 0;           /* EOF : réponse complète */
    if (buf_append(out, tmp, (size_t)n) != 0) return -1;
  }
}

/* Un appel tunnel complet : connecte, envoie la trame, lit jusqu'à EOF.
 * Réponse dans *out (0 ou -1). */
static int cli_call(const char *trame, Buf *out) {
  int fd = tunnel_connect();
  if (fd < 0) {
    log_err("ffsrd injoignable (%s) — est-il actif ? (ffsr d status)",
            strerror(errno));
    return EXIT_ERR;
  }
  if (write(fd, trame, strlen(trame)) != (ssize_t)strlen(trame)) {
    log_err("écriture tunnel: %s", strerror(errno));
    close(fd);
    return EXIT_ERR;
  }
  buf_init(out);
  if (read_until_eof(fd, out, 10) != 0) {
    log_err("ffsrd muet (timeout 10 s) — réponse incomplète ?");
    close(fd);
    buf_free(out);
    return EXIT_ERR;
  }
  close(fd);
  return EXIT_OK;
}

/* Envoie la trame et imprime la réponse sur stdout telle quelle. */
static int send_trame(const char *trame, size_t len) {
  Buf out;
  if (cli_call(trame, &out) != EXIT_OK) return EXIT_ERR;
  if (out.len > 0) fwrite(out.data, 1, out.len, stdout);
  buf_free(&out);
  (void)len;
  return EXIT_OK;
}

/* ------------------------------------------------------------ dispatch */

/* LE hash de la fenêtre dédiée — PREMIÈRE lecture de chaque commande
 * (décision 2026-08-12) : window.sock, servi par ffsrd (résolution
 * fraîche par getTree + state). Le CLI ne devine jamais la fenêtre. */
static int window_hash(char *out, size_t sz) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) { log_err("socket: %s", strerror(errno)); return -1; }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", WINDOW_SOCK);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    log_err("window.sock injoignable (%s) — ffsrd actif ? (ffsr d status)",
            strerror(errno));
    close(fd);
    return -1;
  }
  Buf b;
  buf_init(&b);
  if (read_until_eof(fd, &b, 5) != 0) {
    log_err("window.sock muet (timeout 5 s) — ffsrd occupé ?");
    close(fd);
    buf_free(&b);
    return -1;
  }
  close(fd);
  /* retire le '\n' final éventuel */
  if (b.len > 0 && b.data[b.len - 1] == '\n') b.len--;
  if (b.len == 0) {
    log_err("window.sock: réponse vide — fenêtre dédiée absente ?");
    buf_free(&b);
    return -1;
  }
  size_t l = b.len < sz - 1 ? b.len : sz - 1;
  memcpy(out, b.data, l);
  out[l] = '\0';
  buf_free(&b);
  return 0;
}

/* Extraire la string "value" d'une réponse script.evaluate :
 * {"type":"success","id":N,"result":{"realm":…,"result":{"type":"string",
 * "value":"…"}}} — retourne les bornes ABSOLUES [*start,*end) dans doc. */
static int get_script_value(const char *doc, size_t len,
                            size_t *start, size_t *end) {
  size_t rs = 0, re = 0, rs2 = 0, re2 = 0, vs = 0, ve = 0;
  if (json_value_bounds(doc, len, "result", &rs, &re) != 1) return -1;
  if (json_value_bounds(doc + rs, re - rs, "result", &rs2, &re2) != 1) return -1;
  if (json_get_str_bounds(doc + rs + rs2, re2 - rs2, "value", &vs, &ve)
      != JSON_STR) return -1;
  *start = rs + rs2 + vs;   /* bornes absolues dans doc */
  *end   = rs + rs2 + ve;
  return 0;
}

/* ffsr tabs — LA fenêtre dédiée uniquement, 10 lignes dans l'ordre,
 * format spec : N - URL - title - Ko.
 * IDENTIFICATION : le hash de la fenêtre dédiée vient de window.sock
 * (ffsrd le résout — le CLI ne devine JAMAIS la fenêtre). */
static int cmd_tabs(void) {
  char cw[64];
  if (window_hash(cw, sizeof(cw)) != 0) return EXIT_ERR;

  /* 1. getTree : tous les contextes de premier niveau */
  Buf out;
  if (cli_call("{\"id\":2,\"method\":\"browsingContext.getTree\","
               "\"params\":{\"maxDepth\":0}}", &out) != EXIT_OK) return EXIT_ERR;
  char ctxs[64][64];
  char urls[64][2048];
  char cws[64][64];
  int n = 0;
  {
    size_t rs = 0, re = 0, cs = 0, ce = 0;
    if (json_value_bounds(out.data, out.len, "result", &rs, &re) != 1
        || json_value_bounds(out.data + rs, re - rs, "contexts", &cs, &ce) != 1) {
      log_err("getTree: réponse inattendue");
      buf_free(&out);
      return EXIT_ERR;
    }
    const char *arr = out.data + rs + cs;
    size_t pos = 1, s = 0, e = 0;
    while (n < 64 && json_array_next(arr, ce - cs, &pos, &s, &e) > 0) {
      size_t vs = 0, ve = 0;
      if (json_get_str_bounds(arr + s, e - s, "context", &vs, &ve) != JSON_STR)
        continue;
      size_t cl = ve - vs < sizeof(ctxs[n]) - 1 ? ve - vs
                                                : sizeof(ctxs[n]) - 1;
      memcpy(ctxs[n], arr + s + vs, cl); ctxs[n][cl] = '\0';
      size_t us = 0, ue = 0;
      urls[n][0] = '\0';
      if (json_get_str_bounds(arr + s, e - s, "url", &us, &ue) == JSON_STR) {
        size_t ul = ue - us < sizeof(urls[n]) - 1 ? ue - us
                                                  : sizeof(urls[n]) - 1;
        memcpy(urls[n], arr + s + us, ul); urls[n][ul] = '\0';
      }
      cws[n][0] = '\0';
      if (json_get_str_bounds(arr + s, e - s, "clientWindow", &vs, &ve)
          == JSON_STR) {
        size_t wl = ve - vs < sizeof(cws[n]) - 1 ? ve - vs
                                                 : sizeof(cws[n]) - 1;
        memcpy(cws[n], arr + s + vs, wl); cws[n][wl] = '\0';
      }
      n++;
    }
  }
  buf_free(&out);

  /* 2. les onglets de la fenêtre dédiée, dans l'ordre du getTree */
  int idx = 0;
  for (int i = 0; i < n; i++) {
    if (!cws[i][0] || strcmp(cws[i], cw) != 0) continue;
    char title[512] = "";
    double ko = 0.0;
    char trame[512];
    snprintf(trame, sizeof(trame),
             "{\"id\":3,\"method\":\"script.evaluate\",\"params\":{"
             "\"expression\":\"JSON.stringify({t:document.title,"
             "l:document.documentElement.outerHTML.length})\","
             "\"target\":{\"context\":\"%s\"},"
             "\"awaitPromise\":false,\"resultOwnership\":\"none\"}}",
             ctxs[i]);
    if (cli_call(trame, &out) == EXIT_OK) {
      size_t vs = 0, ve = 0;
      if (get_script_value(out.data, out.len, &vs, &ve) == 0) {
        Buf clean;
        buf_init(&clean);
        if (json_unescape(&clean, out.data + vs, ve - vs) == 0 && clean.len) {
          size_t ts = 0, te = 0;
          long l = 0;
          if (json_get_str_bounds(clean.data, clean.len, "t", &ts, &te)
              == JSON_STR) {
            size_t tl = te - ts < sizeof(title) - 1 ? te - ts
                                                    : sizeof(title) - 1;
            memcpy(title, clean.data + ts, tl);
            title[tl] = '\0';
          }
          if (json_get(clean.data, clean.len, "l", NULL, &l) == JSON_NUM)
            ko = (double)l / 1024.0;
        }
        buf_free(&clean);
      }
      buf_free(&out);
    }
    printf("%d - %s - %s - %.2f Ko\n", idx, urls[i], title, ko);
    idx++;
  }
  if (idx == 0) printf("(aucun onglet dans la fenêtre dédiée)\n");
  return EXIT_OK;
}

static int show_usage(void) {
  printf("ffsr — FireFox Simple Relay (CLI)\n"
         "usage:\n"
         "  ffsr tabs                  | liste les onglets de Firefox\n"
         "  ffsr <trame-json-bidi>     | envoie la trame BiDi via le tunnel\n"
         "  ffsr d status              | état du service (systemctl)\n"
         "  ffsr d start               | systemctl start ffsrd.service\n"
         "  ffsr d stop                | systemctl stop  ffsrd.service\n"
         "  ffsr d restart             | systemctl restart ffsrd.service\n");
  return EXIT_BADARGS;
}

int main(int argc, char **argv) {
  if (argc < 2) return show_usage();

  /* ffsr d … → systemctl (les seules commandes qui touchent ffsrd) */
  if (strcmp(argv[1], "d") == 0) {
    if (argc < 3) {
      log_err("ffsr d demande une sous-commande : status|start|stop|restart");
      return EXIT_BADARGS;
    }
    const char *sub = argv[2];
    const char *action = NULL;
    if      (strcmp(sub, "status")  == 0) action = "status";
    else if (strcmp(sub, "start")   == 0) action = "start";
    else if (strcmp(sub, "stop")    == 0) action = "stop";
    else if (strcmp(sub, "restart") == 0) action = "restart";
    else {
      log_err("ffsr d : sous-commande inconnue '%s'", sub);
      return EXIT_BADARGS;
    }

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "systemctl %s ffsrd.service", action);
    log_msg("$ %s", cmd);
    fflush(NULL);
    execlp("systemctl", "systemctl", action, "ffsrd.service", (char *)NULL);
    log_err("execlp systemctl: %s", strerror(errno));
    return EXIT_ERR;
  }

  /* ffsr tabs — la liste des onglets */
  if (strcmp(argv[1], "tabs") == 0) return cmd_tabs();

  /* Sinon : la trame BiDi est soit donnée telle quelle (JSON entre
   * quotes), soit assemblée par les futures commandes (go/tabs/...).
   * Ce premier jet relaie tout argument brut. */
  const char *trame = argv[1];
  return send_trame(trame, strlen(trame));
}