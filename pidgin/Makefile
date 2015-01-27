# Makefile for Kontalk Pidgin plugin

PACKAGE_NAME = "kontalk"
PACKAGE_VERSION = "0.1"

PREFIX = "/usr"
LOCALEDIR = "$(PREFIX)/locale"

BIN = kontalk.so
OBJS = gpg.o kontalk.o
CC = gcc -c
LD = gcc
CFLAGS = -Wall -fPIC \
	-DPACKAGE_NAME=\"$(PACKAGE_NAME)\" \
	-DPACKAGE_VERSION=\"$(PACKAGE_VERSION)\" \
	-DENABLE_NLS \
	-DGETTEXT_PACKAGE=\"$(PACKAGE_NAME)\" \
	-DLOCALEDIR=\"$(LOCALEDIR)\" \
	-D_FILE_OFFSET_BITS=64 \
	`pkg-config --cflags pidgin` \
	`gpgme-config --cflags`
LDFLAGS = -shared -fPIC `pkg-config --libs pidgin` `gpgme-config --libs`


all: $(BIN)

install: all
	install $(BIN) ~/.purple/plugins

clean:
	rm -f $(BIN) $(OBJS)

$(BIN): $(OBJS)
	$(LD) $(LDFLAGS) -o $(BIN) $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -o $@ $<
