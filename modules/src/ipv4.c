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

#define MAX_EXCLUDES 256

void printSQLSchema(FILE* f) {
  fprintf(f, "CREATE TABLE addresstable (\n");
  fprintf(f, "  hwadr macaddr NOT NULL,\n");
  fprintf(f, "  ipadr inet NOT NULL,\n");
  fprintf(f, "  first_seen timestamp with time zone NOT NULL DEFAULT now(),\n");
  fprintf(f, "  last_seen timestamp with time zone NOT NULL DEFAULT now(),\n");
  fprintf(f, "  bandwidth bigint DEFAULT 0,\n");
  fprintf(f, "  PRIMARY KEY (last_seen, hwadr, ipadr));\n\n");
  fprintf(f, "CREATE OR REPLACE RULE update_addresstable AS\n");
  fprintf(f, "       ON INSERT TO addresstable\n");
  fprintf(f, "       WHERE (SELECT (now() - '00:05:00'::interval) < max(addresstable.last_seen)\n");
  fprintf(f, "              FROM addresstable\n");
  fprintf(f, "              WHERE addresstable.ipadr = new.ipadr\n");
  fprintf(f, "              AND addresstable.hwadr = new.hwadr)\n");
  fprintf(f, "              DO INSTEAD UPDATE addresstable SET last_seen = now()\n");
  fprintf(f, "                                               , bandwidth = addresstable.bandwidth + new.bandwidth\n");
  fprintf(f, "              WHERE addresstable.ipadr = new.ipadr\n");
  fprintf(f, "              AND addresstable.hwadr = new.hwadr\n");
  fprintf(f, "              AND addresstable.last_seen = ((SELECT max(addresstable.last_seen)\n");
  fprintf(f, "                                             FROM addresstable\n");
  fprintf(f, "                                             WHERE addresstable.ipadr = new.ipadr\n");
  fprintf(f, "                                             AND addresstable.hwadr = new.hwadr));\n\n\n");
  fprintf(f, "You can safely change the table name and the column names, make sure you have configured it correctly then.\n");
};

struct ipv4_module_config {
  char* table_name;
  char* macaddr_col;
  char* ipaddr_col;
  char* first_seen;
  char* last_seen;
  char* bandwidth;
  struct connection_struct* database;
  u_char exclude_table[MAX_EXCLUDES][6];
};

void* initContext() {
  struct ipv4_module_config* output = malloc(sizeof(struct ipv4_module_config));
  output->table_name = "addresstable";
  output->macaddr_col = "hwadr";
  output->ipaddr_col = "ipadr";
  output->first_seen = "first_seen";
  output->last_seen = "last_seen";
  output->bandwidth = "bandwidth";
  output->database = NULL;
  memset(&output->exclude_table, 0, sizeof(output->exclude_table));
  return output;
};

void parseConfig(char* key, char* value, void* context) {
  struct ipv4_module_config* ipv4_config = (struct ipv4_module_config*) context;
  if (strcasecmp(key, "table_name") == 0) {
    ipv4_config->table_name = malloc(strlen(value) + 1);
    strcpy(ipv4_config->table_name, value);
  } else if (strcasecmp(key, "macaddr_col") == 0) {
    ipv4_config->macaddr_col = malloc(strlen(value) + 1);
    strcpy(ipv4_config->macaddr_col, value);
  } else if (strcasecmp(key, "ipaddr_col") == 0) {
    ipv4_config->ipaddr_col = malloc(strlen(value) + 1);
    strcpy(ipv4_config->ipaddr_col, value);
  } else if (strcasecmp(key, "first_seen_col") == 0) {
    ipv4_config->first_seen = malloc(strlen(value) + 1);
    strcpy(ipv4_config->first_seen, value);
  } else if (strcasecmp(key, "last_seen_col") == 0) {
    ipv4_config->last_seen = malloc(strlen(value) + 1);
    strcpy(ipv4_config->last_seen, value);
  } else if (strcasecmp(key, "bandwidth_col") == 0) {
    ipv4_config->bandwidth = malloc(strlen(value) + 1);
    strcpy(ipv4_config->bandwidth, value);
  } else if (strcasecmp(key, "exclude") == 0) {
    char mac[6];
    if (sscanf(value, "%02x:%02x:%02x:%02x:%02x:%02x", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
      int i = 0;
      while (ipv4_config->exclude_table[i][0] != 0)
        i++;
      ipv4_config->exclude_table[i][0] = mac[0];
      ipv4_config->exclude_table[i][1] = mac[1];
      ipv4_config->exclude_table[i][2] = mac[2];
      ipv4_config->exclude_table[i][3] = mac[3];
      ipv4_config->exclude_table[i][4] = mac[4];
      ipv4_config->exclude_table[i][5] = mac[5];
    } else
      fprintf(stderr, "There was an error parsing mac address '%s'\n", value);
  }
};

int preCapture(struct event_base* base, char* interface, void* context) {
  struct ipv4_module_config* ipv4_config = (struct ipv4_module_config*) context;
  if (ipv4_config->table_name == NULL || ipv4_config->macaddr_col == NULL || ipv4_config->ipaddr_col == NULL) {
    fprintf(stderr, "You have the ipv4 module loaded, but you don't have it configured properly, "
                    "did you fill in the table_name, macaddr_col and ipaddr_col?\n");
    return 0;
  }
  ipv4_config->database = initDatabase(base);
  ipv4_config->database->report_errors = 1;
  enable_autocommit(ipv4_config->database);
  return 1;
};

char* getPcapRule(void* context) {
  return "ip";
};

int validateMAC(u_char array[], struct ipv4_module_config* ipv4_config) {
  if (array[0] == 0x00 && array[1] == 0x00 && array[2] == 0x00
    && array[3] == 0x00 && array[4] == 0x00 && array[5] == 0x00)
    return 0;
  if (array[0] == 0xFF && array[1] == 0xFF && array[2] == 0xFF
    && array[3] == 0xFF && array[4] == 0xFF && array[5] == 0xFF)
    return 0;
  int i;
  for (i = 0; i < MAX_EXCLUDES; i++) {
    if (ipv4_config->exclude_table[i][0] == 0 && ipv4_config->exclude_table[i][1] == 0
      && ipv4_config->exclude_table[i][2] == 0 && ipv4_config->exclude_table[i][3] == 0
      && ipv4_config->exclude_table[i][4] == 0 && ipv4_config->exclude_table[i][5] == 0)
      break;
    if (ipv4_config->exclude_table[i][0] == array[0] && ipv4_config->exclude_table[i][1] == array[1]
      && ipv4_config->exclude_table[i][2] == array[2] && ipv4_config->exclude_table[i][3] == array[3]
      && ipv4_config->exclude_table[i][4] == array[4] && ipv4_config->exclude_table[i][5] == array[5])
      return 0;
  }
  return 1;
};

void IPv4Callback(struct ethernet_header* ethernet, struct ipv4_header* ipv4, const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  struct ipv4_module_config* ipv4_config = (struct ipv4_module_config*) context;
  char buf[4096];
  if (validateMAC(ethernet->ether_shost, ipv4_config)) {
    snprintf(buf, sizeof(buf), "INSERT INTO %s (%s, %s, %s, %s, %s) "
                               "VALUES ('%02x:%02x:%02x:%02x:%02x:%02x','%s', to_timestamp(%zd.%zd), to_timestamp(%zd.%zd), %d)"
            ,ipv4_config->table_name, ipv4_config->macaddr_col, ipv4_config->ipaddr_col
            ,ipv4_config->first_seen, ipv4_config->last_seen, ipv4_config->bandwidth
            ,ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2]
            ,ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]
            ,inet_ntoa(ipv4->ip_src), pkthdr.ts.tv_sec, pkthdr.ts.tv_usec, pkthdr.ts.tv_sec
            ,pkthdr.ts.tv_usec, pkthdr.caplen);
    databaseQuery(ipv4_config->database, buf, NULL, NULL);
  }
  if (validateMAC(ethernet->ether_dhost, ipv4_config)) {
    snprintf(buf, sizeof(buf), "INSERT INTO %s (%s, %s, %s, %s, %s) "
                               "VALUES ('%02x:%02x:%02x:%02x:%02x:%02x','%s', to_timestamp(%zd.%zd), to_timestamp(%zd.%zd), %d)"
            ,ipv4_config->table_name, ipv4_config->macaddr_col, ipv4_config->ipaddr_col
            ,ipv4_config->first_seen, ipv4_config->last_seen, ipv4_config->bandwidth
            ,ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2]
            ,ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]
            ,inet_ntoa(ipv4->ip_dst), pkthdr.ts.tv_sec, pkthdr.ts.tv_usec, pkthdr.ts.tv_sec
            ,pkthdr.ts.tv_usec, pkthdr.caplen);
    databaseQuery(ipv4_config->database, buf, NULL, NULL);
  }
};