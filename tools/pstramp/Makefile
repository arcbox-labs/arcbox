CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

PREFIX ?= /usr/local

.PHONY: all clean install

all: pstramp

pstramp: pstramp.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f pstramp

install: pstramp
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 pstramp $(DESTDIR)$(PREFIX)/bin/pstramp
