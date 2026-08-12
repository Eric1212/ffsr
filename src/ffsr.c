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

#define SOCK_PATH "/run/ffsrd/ffsr.sock"

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
  char tmp[8192];
  ssize_t n;
  while ((n = read(fd, tmp, sizeof(tmp))) > 0) {
    if (buf_append(out, tmp, (size_t)n) != 0) break;
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
 * format spec : N - URL - title - Ko (title réel via script.evaluate,
 * Ko exacts : taille du HTML / 1024). */
static int cmd_tabs(void) {
  Buf out;

  /* 1. la fenêtre dédiée = la fenêtre ACTIVE (jamais d'ID mémorisé) */
  if (cli_call("{\"id\":1,\"method\":\"browser.getClientWindows\","
               "\"params\":{}}", &out) != EXIT_OK) return EXIT_ERR;
  char cw[64] = "";
  {
    size_t rs = 0, re = 0, ws = 0, we = 0;
    if (json_value_bounds(out.data, out.len, "result", &rs, &re) != 1
        || json_value_bounds(out.data + rs, re - rs, "clientWindows",
                             &ws, &we) != 1) {
      log_err("getClientWindows: réponse inattendue");
      buf_free(&out);
      return EXIT_ERR;
    }
    const char *arr = out.data + rs + ws;
    size_t pos = 1, s = 0, e = 0;
    while (json_array_next(arr, we - ws, &pos, &s, &e) > 0) {
      long active = 0;
      if (json_get(arr + s, e - s, "active", NULL, &active) == JSON_NUM
          && active) {
        size_t vs = 0, ve = 0;
        if (json_get_str_bounds(arr + s, e - s, "clientWindow", &vs, &ve)
            == JSON_STR) {
          size_t l = ve - vs < sizeof(cw) - 1 ? ve - vs : sizeof(cw) - 1;
          memcpy(cw, arr + s + vs, l);
          cw[l] = '\0';
        }
        break;
      }
    }
  }
  buf_free(&out);
  if (!cw[0]) {
    log_err("aucune fenêtre active trouvée");
    return EXIT_ERR;
  }

  /* 2. getTree → les contextes de cette fenêtre, dans l'ordre (0-9) */
  if (cli_call("{\"id\":2,\"method\":\"browsingContext.getTree\","
               "\"params\":{\"maxDepth\":0}}", &out) != EXIT_OK) return EXIT_ERR;
  char ctxs[10][64];
  char urls[10][2048];
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
    while (n < 10 && json_array_next(arr, ce - cs, &pos, &s, &e) > 0) {
      size_t vs = 0, ve = 0;
      if (json_get_str_bounds(arr + s, e - s, "clientWindow", &vs, &ve)
              != JSON_STR)
        continue;
      size_t wl = ve - vs;
      if (wl != strlen(cw) || memcmp(arr + s + vs, cw, wl) != 0) continue;
      size_t us = 0, ue = 0;
      if (json_get_str_bounds(arr + s, e - s, "context", &vs, &ve) == JSON_STR
          && json_get_str_bounds(arr + s, e - s, "url", &us, &ue) == JSON_STR) {
        size_t cl = ve - vs < sizeof(ctxs[n]) - 1 ? ve - vs
                                                  : sizeof(ctxs[n]) - 1;
        size_t ul = ue - us < sizeof(urls[n]) - 1 ? ue - us
                                                  : sizeof(urls[n]) - 1;
        memcpy(ctxs[n], arr + s + vs, cl); ctxs[n][cl] = '\0';
        memcpy(urls[n], arr + s + us, ul); urls[n][ul] = '\0';
        n++;
      }
    }
  }
  buf_free(&out);

  /* 3. titre + taille par onglet (title réel, Ko = HTML/1024) */
  int idx = 0;
  for (int i = 0; i < n; i++) {
    char trame[512];
    snprintf(trame, sizeof(trame),
             "{\"id\":3,\"method\":\"script.evaluate\",\"params\":{"
             "\"expression\":\"JSON.stringify({t:document.title,"
             "l:document.documentElement.outerHTML.length})\","
             "\"target\":{\"context\":\"%s\"},"
             "\"awaitPromise\":false,\"resultOwnership\":\"none\"}}",
             ctxs[i]);
    if (cli_call(trame, &out) != EXIT_OK) continue;
    size_t vs = 0, ve = 0;
    char title[512] = "";
    double ko = 0.0;
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