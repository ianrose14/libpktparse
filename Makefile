CC=gcc
CFLAGS=-ansi -std=c99 -pedantic -Wall -Werror -Iinclude -I $(HOME)/include -fPIC -O3 -L $(HOME)/lib

SRCS=$(shell find src -name \*.c)
OBJS=$(addprefix obj/, $(addsuffix .o, $(notdir $(basename $(SRCS)))))
INCLUDES=$(shell find include -name \*.h)

# shared library version:
VERSION=1

# List of all files that should be pushed to remote nodes (with the path they
# should use on the remote node; not the local path)
REL_DEPS=bin/pcap-print lib/libpktparse.so.$(VERSION) lib/libpktparse.so $(INCLUDES)

# boilerplate:
DEPS=$(foreach file, $(REL_DEPS), $(DEPLOY)/$(file))
DEPDIRS=$(foreach file, $(REL_DEPS), $(DEPLOY)/$(dir $(file)))

.PHONY: all clean deployment dirs init install
.SECONDARY:

# phony targets:

all: lib/libpktparse.so bin/pcap-print

clean:
	rm -f bin/* lib/* obj/* src/*~ include/*~

deployment: init dirs $(DEPS) install

dirs:
	@mkdir -p $(DEPDIRS)

init: all
ifndef DEPLOY
	$(error DEPLOY not specified)
endif

install: all
	mkdir -p ~/lib ~/bin ~/include
	cp -R -P lib/lib* ~/lib
	cp bin/pcap-print ~/bin
	cp include/* ~/include

# real targets:

$(DEPLOY)/%: %
	cp -R -P $< $@

lib/libpktparse.so.%: obj/pktparse.o obj/pktparse-print.o
	@mkdir -p lib
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(shell basename $@) -o $@ $^

lib/libpktparse.so: lib/libpktparse.so.$(VERSION)
	ln -fs $(shell basename $^) $@

bin/pcap-print: obj/pcap-print.o lib/libpktparse.so
	@mkdir -p bin
	$(CC) $(CFLAGS) -o $@ $< -rpath $(HOME)/lib -Llib -lpcap -lpktparse

obj/%.o: src/%.c $(INCLUDES) Makefile
	@mkdir -p obj
	$(CC) $(CFLAGS) -c -o $@ $<
