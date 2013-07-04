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
  char* table_name;
  char* macaddr_col;
  char* ipaddr_col;
  char* server_ip_col;
  char* timestamp_col;
  char* question_col;
};

void* initContext() {
  struct dns_module_config* output = malloc(sizeof(struct dns_module_config));
  output->dns = malloc(sizeof(dns_info));
  output->conf = malloc(sizeof(config));
  output->table_name = "dnsquestions";
  output->macaddr_col = "hwadr";
  output->ipaddr_col = "ipadr";
  output->server_ip_col = "server";
  output->timestamp_col = "timestamp";
  output->question_col = "question";
  return output;
};

void printSQLSchema(FILE* f) {
  fprintf(f, "CREATE TABLE dnsquestions(\n");
  fprintf(f, "  hwadr macaddr NOT NULL,\n");
  fprintf(f, "  ipadr inet,\n");
  fprintf(f, "  server inet,\n");
  fprintf(f, "  \"timestamp\" timestamp with time zone NOT NULL,\n");
  fprintf(f, "  question character varying(128) NOT NULL,\n");
  fprintf(f, "  CONSTRAINT dnsquestions_pkey PRIMARY KEY (hwadr, question, \"timestamp\"))\n\n\n");
  fprintf(f, "You can safely change the table name and the column names, make sure you have configured it correctly then.\n");
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

void IPv4UDPCallback(struct ethernet_header* eth, struct ipv4_header* ipv4, struct udp_header* udp, const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  struct dns_module_config* dns_config = (struct dns_module_config*) context;
  if (dns_parse(((void*)udp-(void*)packet)+SIZE_UDP, &pkthdr, (uint8_t*) packet, dns_config->dns, dns_config->conf, 1) != 0
    && !dns_config->dns->answers) {
    dns_question* q = dns_config->dns->queries;
    while (q) {
      char buf[BUFSIZ];
      char src[INET_ADDRSTRLEN];
      char dst[INET_ADDRSTRLEN];
      snprintf(buf, sizeof(buf), "INSERT INTO %s (%s, %s, %s, %s, %s) VALUES "
                                 "('%02X:%02X:%02X:%02X:%02X:%02X', '%s', '%s', to_timestamp(%zd.%zd), '%s')"
              ,dns_config->table_name, dns_config->macaddr_col, dns_config->ipaddr_col
              ,dns_config->server_ip_col, dns_config->timestamp_col, dns_config->question_col
              ,eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2]
              ,eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]
              ,inet_ntop(AF_INET, &ipv4->ip_src, src, INET_ADDRSTRLEN)
              ,inet_ntop(AF_INET, &ipv4->ip_dst, dst, INET_ADDRSTRLEN)
              ,pkthdr.ts.tv_sec, pkthdr.ts.tv_usec
              ,q->name);
      databaseQuery(dns_config->database, buf, NULL, NULL);
      q = q->next;
    }
    dns_question_free(dns_config->dns->queries);
    dns_rr_free(dns_config->dns->answers);
    dns_rr_free(dns_config->dns->name_servers);
    dns_rr_free(dns_config->dns->additional);
  }
};