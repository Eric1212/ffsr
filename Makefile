# ffsr — Makefile (spec : make = 2 binaires ; make install = système)

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
CFLAGS  += $(shell pkg-config --cflags libcurl)
LDLIBS   = $(shell pkg-config --libs libcurl)

SRC     = src
BIN     = ffsr ffsrd

PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
UNITDIR     ?= /usr/lib/systemd/system
CONFDIR     ?= /etc/ffsrd
SOCKDIR     ?= /run/ffsrd
STATEDIR    ?= /var/lib/ffsrd

all: $(BIN)

ffsr: $(SRC)/ffsr.c $(SRC)/common.c $(SRC)/common.h
	$(CC) $(CFLAGS) -o $@ $(SRC)/ffsr.c $(SRC)/common.c $(LDLIBS)

ffsrd: $(SRC)/ffsrd.c $(SRC)/common.c $(SRC)/common.h
	$(CC) $(CFLAGS) -o $@ $(SRC)/ffsrd.c $(SRC)/common.c $(LDLIBS)

install: all
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(UNITDIR) \
	           $(DESTDIR)$(CONFDIR) $(DESTDIR)$(SOCKDIR) \
	           $(DESTDIR)$(STATEDIR)
	install -m 0755 ffsr ffsrd $(DESTDIR)$(BINDIR)/
	install -m 0644 systemd/ffsrd.service $(DESTDIR)$(UNITDIR)/
	install -m 0644 etc/ffsrd.conf $(DESTDIR)$(CONFDIR)/conf
	@echo "==> systemctl daemon-reload && systemctl enable --now ffsrd"
	-systemctl daemon-reload
	-systemctl enable ffsrd.service
	# restart (pas --now) : un service déjà actif garde l'ANCIEN binaire en
	# mémoire — chaque make install doit être effectif immédiatement.
	-systemctl restart ffsrd.service

uninstall:
	-rm -f $(DESTDIR)$(BINDIR)/ffsr $(DESTDIR)$(BINDIR)/ffsrd
	-rm -f $(DESTDIR)$(UNITDIR)/ffsrd.service
	-systemctl disable --now ffsrd.service 2>/dev/null || true

clean:
	rm -f $(BIN)

.PHONY: all install uninstall clean