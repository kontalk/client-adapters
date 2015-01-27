# Makefile for Kontalk Pidgin plugin

BIN = kontalk.so
OBJS = kontalk.o
CC = gcc -c
LD = gcc
CFLAGS = -Wall `pkg-config --cflags pidgin`
LDFLAGS = -shared `pkg-config --libs pidgin`


all: $(BIN)

install: all
	install $(BIN) ~/.purple/plugins

clean:
	rm -f $(BIN) $(OBJS)

$(BIN): $(OBJS)
	$(LD) $(LDFLAGS) -o $(BIN) $<

.c.o:
	$(CC) $(CFLAGS) -o $@ $<
