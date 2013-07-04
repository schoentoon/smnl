CFLAGS := $(CFLAGS) -Wall -O2 -mtune=native -g -shared -fPIC
CC     := gcc
OBJ    := dns_parse.o rtypes.o strutils.o network.o tcp.o

all: $(OBJ)

dns_parse.o: dns_parse.c
	$(CC) $(CFLAGS) -c dns_parse.c

rtypes.o: rtypes.c rtypes.h
	$(CC) $(CFLAGS) -c rtypes.c

strutils.o: strutils.h strutils.c
	$(CC) $(CFLAGS) -c strutils.c

tcp.o: tcp.h tcp.c dns_parse.h
	$(CC) $(CFLAGS) -c tcp.c

network.o: network.h network.c dns_parse.h
	$(CC) $(CFLAGS) -c network.c

clean:
	rm -rfv *.o
