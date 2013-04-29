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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <event2/event.h>

/*
  Table for this module sort of looks like this
  CREATE TABLE public.arptable (
   hwadr macaddr,
   ipadr inet,
   PRIMARY KEY (hwadr, ipadr));
 */

struct arp_module_config {
  char* table_name;
  char* macaddr_col;
  char* ipaddr_col;
};

void* initContext() {
  struct arp_module_config* output = malloc(sizeof(struct arp_module_config));
  output->table_name = "public.arptable";
  output->macaddr_col = "hwadr";
  output->ipaddr_col = "ipadr";
  return output;
};

void parseConfig(char* key, char* value, void* context) {
  struct arp_module_config* arp_config = (struct arp_module_config*) context;
  if (strcasecmp(key, "table_name") == 0) {
    arp_config->table_name = malloc(strlen(value) + 1);
    strcpy(arp_config->table_name, value);
  } else if (strcasecmp(key, "macaddr_col") == 0) {
    arp_config->macaddr_col = malloc(strlen(value) + 1);
    strcpy(arp_config->macaddr_col, value);
  } else if (strcasecmp(key, "ipaddr_col") == 0) {
    arp_config->ipaddr_col = malloc(strlen(value) + 1);
    strcpy(arp_config->ipaddr_col, value);
  }
};

char* getPcapRule(void* context) {
  return "arp";
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

void queryCallback(PGresult* res, void* context, char* query) {
  if (PQresultStatus(res) != PGRES_COMMAND_OK)
    fprintf(stderr, "Query: '%s' returned error\n\t%s\n", query, PQresultErrorMessage(res));
};

void rawPacketCallback(const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  arphdr_t *arp = (struct arphdr*) (packet + 14);
  if ((arp->tha[0] == 0x00 && arp->tha[1] == 0x00 && arp->tha[2] == 0x00
      && arp->tha[3] == 0x00 && arp->tha[4] == 0x00 && arp->tha[5] == 0x00)
      || (arp->tha[0] == 0xFF && arp->tha[1] == 0xFF && arp->tha[2] == 0xFF
      && arp->tha[3] == 0xFF && arp->tha[4] == 0xFF && arp->tha[5] == 0xFF))
    return;
  if (ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x0800) {
    struct arp_module_config* arp_config = (struct arp_module_config*) context;
    char buf[4096];
    snprintf(buf, sizeof(buf), "BEGIN;INSERT INTO %s (%s, %s) VALUES "
                               "('%02X:%02X:%02X:%02X:%02X:%02X', '%d.%d.%d.%d');COMMIT;"
                               ,arp_config->table_name, arp_config->macaddr_col, arp_config->ipaddr_col
                               ,arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]
                               ,arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
    databaseQuery(buf, queryCallback, NULL);
    snprintf(buf, sizeof(buf), "BEGIN;INSERT INTO %s (%s, %s) VALUES "
                               "('%02X:%02X:%02X:%02X:%02X:%02X', '%d.%d.%d.%d');COMMIT;"
                               ,arp_config->table_name, arp_config->macaddr_col, arp_config->ipaddr_col
                               ,arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]
                               ,arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);
    databaseQuery(buf, queryCallback, NULL);
  }
};