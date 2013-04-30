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

char* getPcapRule(void* context) {
  return "ip";
};

void queryCallback(PGresult* res, void* context, char* query) {
  if (PQresultStatus(res) != PGRES_COMMAND_OK)
    fprintf(stderr, "Query: '%s' returned error\n\t%s\n", query, PQresultErrorMessage(res));
};

void IPv4Callback(struct ethernet_header* ethernet, struct ipv4_header* ipv4, const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  fprintf(stderr, "From: %02x:%02x:%02x:%02x:%02x:%02x\t"
         ,ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2]
         ,ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
  fprintf(stderr, "ip: %s\n", inet_ntoa(ipv4->ip_src));
  char buf[4096];
  snprintf(buf, sizeof(buf), "BEGIN;INSERT INTO addresstable (hwadr, ipadr) VALUES ('%02x:%02x:%02x:%02x:%02x:%02x','%s');COMMIT;"
          ,ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2]
          ,ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]
          ,inet_ntoa(ipv4->ip_src));
  databaseQuery(buf, queryCallback, NULL);
  snprintf(buf, sizeof(buf), "BEGIN;INSERT INTO addresstable (hwadr, ipadr) VALUES ('%02x:%02x:%02x:%02x:%02x:%02x','%s');COMMIT;"
          ,ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2]
          ,ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]
          ,inet_ntoa(ipv4->ip_dst));
  databaseQuery(buf, queryCallback, NULL);
};