CFLAGS := $(CFLAGS) -Wall -O2 -mtune=native -g
MFLAGS := -shared -fPIC
INC    := -Iinclude -I/usr/include/postgresql $(INC)
LFLAGS := -levent -lpq -ldl -lpcap -lm -Wl,--export-dynamic
DEFINES:= $(DEFINES)
CC     := gcc
BINARY := smnl
MODULES:= modules/sample.so modules/arp.so modules/ipv4.so
DEPS   := build/main.o build/postgres.o build/config.o build/headers.o build/iputils.o

.PHONY: all clean dev clang modules

all: build bin/$(BINARY) modules

dev: clean
	DEFINES="-DDEV" $(MAKE)

build:
	-mkdir -p build bin

modules: $(MODULES)

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

modules/sample.so: modules/src/sample.c
	$(CC) $(CFLAGS) $(MFLAGS) $(DEFINES) $(INC) -o modules/sample.so modules/src/sample.c

modules/arp.so: modules/src/arp.c
	$(CC) $(CFLAGS) $(MFLAGS) $(DEFINES) $(INC) -o modules/arp.so modules/src/arp.c

modules/ipv4.so: modules/src/ipv4.c
	$(CC) $(CFLAGS) $(MFLAGS) $(DEFINES) $(INC) -Wno-format -o modules/ipv4.so modules/src/ipv4.c

clean:
	rm -rfv bin/$(BINARY) $(DEPS) $(MODULES)

setcaps: bin/$(BINARY)
	sudo setcap cap_net_raw+ep bin/$(BINARY)

install:
	cp bin/$(BINARY) /usr/bin/$(BINARY)

clang:
	$(MAKE) CC=clang
