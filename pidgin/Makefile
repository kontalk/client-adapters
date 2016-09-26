# Makefile for Kontalk Pidgin plugin

PACKAGE_NAME = "kontalk"
PACKAGE_VERSION = "0.1"

PREFIX = "/usr"
LOCALEDIR = "$(PREFIX)/locale"

BIN = kontalk.so
OBJS = gpg.o cpim.o kontalk.o
PKGCONFIG_DEPS = pidgin
CC = gcc -c
LD = gcc
CFLAGS = -Wall -fPIC \
	-DPACKAGE_NAME=\"$(PACKAGE_NAME)\" \
	-DPACKAGE_VERSION=\"$(PACKAGE_VERSION)\" \
	-DENABLE_NLS \
	-DGETTEXT_PACKAGE=\"$(PACKAGE_NAME)\" \
	-DLOCALEDIR=\"$(LOCALEDIR)\" \
	-D_FILE_OFFSET_BITS=64 \
	`pkg-config --cflags $(PKGCONFIG_DEPS)` \
	`gpgme-config --cflags`
LDFLAGS = -shared -fPIC `pkg-config --libs $(PKGCONFIG_DEPS)` `gpgme-config --libs`


all: $(BIN)

install: all
	install $(BIN) ~/.purple/plugins

clean:
	rm -f $(BIN) $(OBJS)

$(BIN): $(OBJS)
	$(LD) -o $(BIN) $(OBJS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -o $@ $<
