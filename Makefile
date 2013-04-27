CFLAGS := $(CFLAGS) -Wall -O2 -mtune=native -g
MFLAGS := -shared -fPIC
INC    := -Iinclude -I/usr/include/postgresql $(INC)
LFLAGS := -levent -lpq -ldl
DEFINES:= $(DEFINES)
CC     := gcc
BINARY := smnl
MODULES:= modules/sample.so
DEPS   := build/main.o build/postgres.o build/config.o

.PHONY: all clean dev clang modules

all: build bin/smnl modules

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

bin/smnl: $(DEPS)
	$(CC) $(CFLAGS) $(DEFINES) $(INC) -o bin/$(BINARY) $(DEPS) $(LFLAGS)

modules/sample.so: modules/src/sample.c
	$(CC) $(CFLAGS) $(MFLAGS) $(DEFINES) $(INC) -o modules/sample.so modules/src/sample.c

clean:
	rm -rfv bin/$(BINARY) $(DEPS) $(MODULES)

install:
	cp bin/$(BINARY) /usr/bin/$(BINARY)

clang:
	$(MAKE) CC=clang