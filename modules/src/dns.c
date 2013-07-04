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
#ifdef UDP
#undef UDP
#endif
#include "dns_parse/dns_parse.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct dns_module_config {
  struct connection_struct* database;
  dns_info* dns;
  config* conf;
};

void* initContext() {
  struct dns_module_config* output = malloc(sizeof(struct dns_module_config));
  output->dns = malloc(sizeof(dns_info));
  output->conf = malloc(sizeof(config));
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
  if (dns_parse(((void*)udp-(void*)packet)+SIZE_UDP, &pkthdr, (uint8_t*) packet, dns_config->dns, dns_config->conf, 1) != 0) {
    dns_question* q = dns_config->dns->queries;
    while (q) {
      printf("Question %s\n", q->name);
      q = q->next;
    }
  }
};