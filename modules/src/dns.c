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
#include "postgres.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

struct dns_header {
    /* RFC 1035, section 4.1 */
    /* This is only the DNS header, the sections (Question, Answer, etc) follow */
    uint16_t        query_id;
    uint16_t        codes;
    uint16_t        qdcount, ancount, nscount, arcount;
};

#define DNS_QR(dns)             ((ntohs((dns)->codes) & 0x8000) >> 15)
#define DNS_OPCODE(dns) ((ntohs((dns)->codes) >> 11) & 0x000F)
#define DNS_RCODE(dns)  (ntohs((dns)->codes) & 0x000F)
#define DNS_AA(dns)   ((ntohs((dns)->codes) & 0x0400) >> 10)
#define DNS_TC(dns)   ((ntohs((dns)->codes) & 0x0200) >> 9)
#define DNS_RD(dns)   ((ntohs((dns)->codes) & 0x0100) >> 8)
#define DNS_RA(dns)   ((ntohs((dns)->codes) & 0x0080) >> 7)

struct dns_module_config {
  struct connection_struct* database;
};

void* initContext() {
  struct dns_module_config* output = malloc(sizeof(struct dns_module_config));
  return output;
};

int preCapture(struct event_base* base, char* interface, void* context) {
  struct dns_module_config* dns_config = (struct dns_module_config*) context;
  dns_config->database = initDatabase(base);
  dns_config->database->report_errors = 1;
  enable_autocommit(dns_config->database);
  return 1;
};

char* getPcapRule(void* context) {
  return "port 53";
};

void IPv4UDPCallback(struct ethernet_header* ethernet, struct ipv4_header* ipv4, struct udp_header* udp, const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  fprintf(stderr, "IPv4UDPCallback(%p, %p, %p, %p);\n", ethernet, ipv4, udp, context);
  struct dns_module_config* dns_config = (struct dns_module_config*) context;
  struct dns_header* dns_header = (struct dns_header*) (udp + SIZE_UDP);
  if (DNS_QR(dns_header) == 0) {
    fprintf(stderr, "DNS Query\n");
    int i;
    for (i = 0; i < pkthdr.caplen; i++)
      fprintf(stderr, "0x%x %c\n", packet[i], packet[i]);
  }
};