CFLAGS := $(CFLAGS) -Wall -O2 -mtune=native -g
MFLAGS := -shared -fPIC
INC    := -I../include -I/usr/include/postgresql $(INC)
DEFINES:= $(DEFINES)
CC     := gcc
MODULES:= sample.so arp.so ipv4.so dns.so

all: $(MODULES)

sample.so: src/sample.c
	$(CC) $(CFLAGS) $(MFLAGS) $(DEFINES) $(INC) -o sample.so src/sample.c

arp.so: src/arp.c
	$(CC) $(CFLAGS) $(MFLAGS) $(DEFINES) $(INC) -o arp.so src/arp.c

ipv4.so: src/ipv4.c
	$(CC) $(CFLAGS) $(MFLAGS) $(DEFINES) $(INC) -Wno-format -o ipv4.so src/ipv4.c

dns_parse:
	$(MAKE) -C src/dns_parse

dns.so: src/dns.c dns_parse
	$(CC) $(CFLAGS) $(MFLAGS) $(DEFINES) $(INC) -Wno-format -o dns.so src/dns.c src/dns_parse/*.o

clean:
	rm -rfv $(MODULES)
	$(MAKE) -C src/dns_parse clean

clang:
	$(MAKE) CC=clang