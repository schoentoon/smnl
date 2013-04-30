/*  smnl
 *  Copyright (C) 2013  Toon Schoenmakers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "headers.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <event2/event.h>

void* initContext() {
  fprintf(stderr, "initContext();\n");
  return (void*) 0xDEADBEEF; /* Spoiler alert, not an actual valid pointer. */
};

void parseConfig(char* key, char* value, void* context) {
  fprintf(stderr, "parseConfig('%s', '%s', %p);\n", key, value, context);
};

char* getPcapRule(void* context) {
  fprintf(stderr, "getPcapRule(%p);\n", context);
  return "";
};

int preCapture(struct event_base* base, char* interface, void* context) {
  fprintf(stderr, "preCapture(%p, '%s', %p);\n", base, interface, context);
  return 1;
};

void IPv4UDPCallback(struct ipv4_header* ipv4, struct udp_header* udp, void* context) {
  fprintf(stderr, "IPv4UDPCallback(%p, %p, %p);\n", ipv4, udp, context);
};

void rawPacketCallback(const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  fprintf(stderr, "packetCallback(%p, %p, %p);\n", packet, &pkthdr, context);
};