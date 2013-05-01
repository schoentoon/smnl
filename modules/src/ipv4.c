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

struct ipv4_module_config {
  char* table_name;
  char* macaddr_col;
  char* ipaddr_col;
  struct connection_struct* database;
};

void* initContext() {
  struct ipv4_module_config* output = malloc(sizeof(struct ipv4_module_config));
  output->table_name = NULL;
  output->macaddr_col = NULL;
  output->ipaddr_col = NULL;
  output->database = NULL;
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
  ipv4_config->database->autocommit = 255;
  return 1;
};

char* getPcapRule(void* context) {
  return "ip";
};

void IPv4Callback(struct ethernet_header* ethernet, struct ipv4_header* ipv4, const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  struct ipv4_module_config* ipv4_config = (struct ipv4_module_config*) context;
  char buf[4096];
  snprintf(buf, sizeof(buf), "INSERT INTO %s (%s, %s) VALUES ('%02x:%02x:%02x:%02x:%02x:%02x','%s')"
          ,ipv4_config->table_name, ipv4_config->macaddr_col, ipv4_config->ipaddr_col
          ,ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2]
          ,ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]
          ,inet_ntoa(ipv4->ip_src));
  databaseQuery(ipv4_config->database, buf, NULL, NULL);
  snprintf(buf, sizeof(buf), "INSERT INTO %s (%s, %s) VALUES ('%02x:%02x:%02x:%02x:%02x:%02x','%s')"
          ,ipv4_config->table_name, ipv4_config->macaddr_col, ipv4_config->ipaddr_col
          ,ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2]
          ,ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]
          ,inet_ntoa(ipv4->ip_dst));
  databaseQuery(ipv4_config->database, buf, NULL, NULL);
};