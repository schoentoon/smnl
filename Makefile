CFLAGS := $(CFLAGS) -Wall -O2 -mtune=native -g
INC    := -Iinclude -I/usr/include/postgresql $(INC)
LFLAGS := -levent -lpq
DEFINES:= $(DEFINES)
CC     := gcc
BINARY := smnl
DEPS   := build/main.o build/postgres.o build/config.o

.PHONY: all clean dev

all: build bin/smnl

dev: clean
	DEFINES="-DDEV" $(MAKE)

build:
	-mkdir -p build bin

build/main.o: src/main.c
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -c -o build/main.o src/main.c

build/postgres.o: src/postgres.c include/postgres.h
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -c -o build/postgres.o src/postgres.c

build/config.o: src/config.c include/config.h
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -Wno-format -c -o build/config.o src/config.c

bin/smnl: $(DEPS)
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -o bin/$(BINARY) $(DEPS) $(LFLAGS)

clean:
	rm -rfv build bin

install:
	cp bin/$(BINARY) /usr/bin/$(BINARY)

clang:
	$(MAKE) dev CC=clang
