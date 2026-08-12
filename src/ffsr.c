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

/* Envoie la trame et imprime la réponse sur stdout telle quelle. */
static int send_trame(const char *trame, size_t len) {
  int fd = tunnel_connect();
  if (fd < 0) {
    log_err("ffsrd injoignable (%s) — est-il actif ? (ffsr d status)",
            strerror(errno));
    return EXIT_ERR;
  }

  if (write(fd, trame, len) != (ssize_t)len) {
    log_err("écriture tunnel: %s", strerror(errno));
    close(fd);
    return EXIT_ERR;
  }

  /* Réponse : on lit jusqu'à EOF (le daemon fermera côté client
   * quand la réponse sera relayée — TODO jet 2 : convention de fin,
   * p.ex. le daemon ferme la connexion client après réponse/réponses). */
  Buf out;
  buf_init(&out);
  char tmp[8192];
  ssize_t n;
  while ((n = read(fd, tmp, sizeof(tmp))) > 0) {
    if (buf_append(&out, tmp, (size_t)n) != 0) break;
  }
  close(fd);

  if (out.len > 0) fwrite(out.data, 1, out.len, stdout);
  buf_free(&out);
  return EXIT_OK;
}

/* ------------------------------------------------------------ dispatch */

static int show_usage(void) {
  printf("ffsr — FireFox Simple Relay (CLI)\n"
         "usage:\n"
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

  /* Sinon : la trame BiDi est soit donnée telle quelle (JSON entre
   * quotes), soit assemblée par les futures commandes (go/tabs/...).
   * Ce premier jet relaie tout argument brut. */
  const char *trame = argv[1];
  return send_trame(trame, strlen(trame));
}