CFLAGS := $(CFLAGS) -Wall -O2 -mtune=native -g
INC    := -Iinclude -I/usr/include/postgresql $(INC)
LFLAGS := -levent -lpq -ldl -lpcap -lm -Wl,--export-dynamic
DEFINES:= $(DEFINES)
CC     := gcc
BINARY := smnl
DEPS   := build/main.o build/postgres.o build/config.o build/headers.o build/iputils.o

.PHONY: all clean dev clang modules

all: build bin/$(BINARY) modules

dev: clean
	DEFINES="-DDEV" $(MAKE)

build:
	-mkdir -p build bin

modules:
	$(MAKE) -C modules

build/main.o: src/main.c
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -c -o build/main.o src/main.c

build/postgres.o: src/postgres.c include/postgres.h
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -c -o build/postgres.o src/postgres.c

build/config.o: src/config.c include/config.h
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -Wno-format -c -o build/config.o src/config.c

build/headers.o: src/headers.c include/headers.h
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -c -o build/headers.o src/headers.c

build/iputils.o: src/iputils.c include/iputils.h
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -c -o build/iputils.o src/iputils.c

bin/smnl: $(DEPS)
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -o bin/$(BINARY) $(DEPS) $(LFLAGS)

clean:
	rm -rfv bin/$(BINARY) $(DEPS)
	$(MAKE) -C modules clean

setcaps: bin/$(BINARY)
	sudo setcap cap_net_raw+ep bin/$(BINARY)

install:
	cp bin/$(BINARY) /usr/bin/$(BINARY)

clang:
	$(MAKE) CC=clang