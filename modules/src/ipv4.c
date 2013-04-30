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

struct ipv4_module_config {
  struct connection_struct* database;
};

void* initContext() {
  struct ipv4_module_config* output = malloc(sizeof(struct ipv4_module_config));
  output->database = NULL;
  return output;
};

int preCapture(struct event_base* base, char* interface, void* context) {
  struct ipv4_module_config* ipv4_config = (struct ipv4_module_config*) context;
  ipv4_config->database = initDatabase(base);
  return 1;
};

char* getPcapRule(void* context) {
  return "ip";
};

void queryCallback(PGresult* res, void* context, char* query) {
  if (PQresultStatus(res) != PGRES_COMMAND_OK)
    fprintf(stderr, "Query: '%s' returned error\n\t%s\n", query, PQresultErrorMessage(res));
};

void IPv4Callback(struct ethernet_header* ethernet, struct ipv4_header* ipv4, const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  struct ipv4_module_config* ipv4_config = (struct ipv4_module_config*) context;
  fprintf(stderr, "From: %02x:%02x:%02x:%02x:%02x:%02x\t"
         ,ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2]
         ,ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
  fprintf(stderr, "ip: %s\n", inet_ntoa(ipv4->ip_src));
  char buf[4096];
  databaseQuery(ipv4_config->database, "BEGIN", queryCallback, NULL);
  snprintf(buf, sizeof(buf), "BEGIN;INSERT INTO addresstable (hwadr, ipadr) VALUES ('%02x:%02x:%02x:%02x:%02x:%02x','%s');COMMIT;"
          ,ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2]
          ,ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]
          ,inet_ntoa(ipv4->ip_src));
  databaseQuery(ipv4_config->database, buf, queryCallback, NULL);
  snprintf(buf, sizeof(buf), "BEGIN;INSERT INTO addresstable (hwadr, ipadr) VALUES ('%02x:%02x:%02x:%02x:%02x:%02x','%s');COMMIT;"
          ,ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2]
          ,ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]
          ,inet_ntoa(ipv4->ip_dst));
  databaseQuery(ipv4_config->database, buf, queryCallback, NULL);
  databaseQuery(ipv4_config->database, "COMMIT", queryCallback, NULL);
};