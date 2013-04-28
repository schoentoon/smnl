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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <event2/event.h>

struct test {
  char* testvar;
};

void* initContext() {
  fprintf(stderr, "initContext();\n");
  return malloc(sizeof(struct test));
};

void parseConfig(char* key, char* value, void* context) {
  fprintf(stderr, "parseConfig('%s', '%s', %p);\n", key, value, context);
  if (strcmp(key, "test") == 0) {
    fprintf(stderr, "Value is %s.\n", value);
    struct test* ctx = (struct test*) context;
    ctx->testvar = malloc(strlen(value) + 1);
    strcpy(ctx->testvar, value);
  }
};

char* getPcapRule(void* context) {
  fprintf(stderr, "getPcapRule(%p);\n", context);
  return "arp";
};

int preCapture(struct event_base* base) {
  fprintf(stderr, "preCapture(%p);\n", base);
  return 1;
};

#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct arphdr {
  u_int16_t htype;
  u_int16_t ptype;
  u_char hlen;
  u_char plen;
  u_int16_t oper;
  u_char sha[6];
  u_char spa[4];
  u_char tha[6];
  u_char tpa[4];
} arphdr_t;

void packetCallback(const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  fprintf(stderr, "packetCallback(%p, %p, %p);\n", packet, &pkthdr, context);
  arphdr_t *arpheader = (struct arphdr*) (packet + 14);
  if ((arpheader->tha[0] == 0x00 && arpheader->tha[1] == 0x00 && arpheader->tha[2] == 0x00
    && arpheader->tha[3] == 0x00 && arpheader->tha[4] == 0x00 && arpheader->tha[5] == 0x00)
    || (arpheader->tha[0] == 0xFF && arpheader->tha[1] == 0xFF && arpheader->tha[2] == 0xFF
    && arpheader->tha[3] == 0xFF && arpheader->tha[4] == 0xFF && arpheader->tha[5] == 0xFF))
    return;
  printf("Received Packet Size: %d bytes\n", pkthdr.len);
  printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
  printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
  printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");
  if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) {
    int i;
    printf("Sender MAC: ");
    for (i = 0; i < 6; i++)
      printf("%02X%s", arpheader->sha[i], (i != 5) ? ":" : "");
    printf("\nSender IP: ");
    for (i = 0; i < 4; i++)
      printf("%d%s", arpheader->spa[i], (i != 3) ? "." : "");
    printf("\nTarget MAC: ");
    for(i = 0; i < 6; i++)
      printf("%02X%s", arpheader->tha[i], (i != 5) ? ":" : "");
    printf("\nTarget IP: ");
    for(i = 0; i < 4; i++)
      printf("%d%s", arpheader->tpa[i], (i != 3) ? "." : "");
    printf("\n");
  }
};