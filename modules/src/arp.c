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

#include "iputils.h"
#include "headers.h"
#include "postgres.h"

#include <pcap.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

#include <event2/event.h>

/*
  You can create a nice table with essentially the running time of
  a subnet of hosts with this module (assuming you have the prober on).
  You just need your table to look something like this, the rule here is important.
  As without it most insert queries would fail (and therefor your transactions would
  abort). If you really want to have this table with running time of hosts keep in
  mind that mobile devices handle arp slightly different making this method kind of
  unreliable. If you're running this on a gateway you can essentially update this
  table using the data coming from that (ipv4.so) to make it more relialble.

  CREATE TABLE arptable (hwadr macaddr NOT NULL
                        ,ipadr inet NOT NULL
                        ,first_seen timestamp with time zone NOT NULL DEFAULT now()
                        ,last_seen timestamp with time zone NOT NULL DEFAULT now()
                        ,CONSTRAINT arptable_pkey PRIMARY KEY (last_seen, hwadr, ipadr));

  CREATE OR REPLACE RULE update_arptable AS
         ON INSERT TO arptable
  WHERE (SELECT (now() - '00:05:00'::interval) < max(arptable.last_seen)
         FROM arptable
         WHERE arptable.ipadr = new.ipadr
         AND arptable.hwadr = new.hwadr)
         DO INSTEAD UPDATE arptable SET last_seen = now()
                    WHERE arptable.ipadr = new.ipadr
                    AND arptable.hwadr = new.hwadr
                    AND arptable.last_seen = (SELECT max(arptable.last_seen) AS max
                                              FROM arptable
                                              WHERE arptable.ipadr = new.ipadr
                                              AND arptable.hwadr = new.hwadr);
 */

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAX_RANGES 256

void printSQLSchema(FILE* f) {
  fprintf(f, "CREATE TABLE arptable (hwadr macaddr NOT NULL\n");
  fprintf(f, "                      ,ipadr inet NOT NULL\n");
  fprintf(f, "                      ,first_seen timestamp with time zone NOT NULL DEFAULT now()\n");
  fprintf(f, "                      ,last_seen timestamp with time zone NOT NULL DEFAULT now()\n");
  fprintf(f, "                      ,CONSTRAINT arptable_pkey PRIMARY KEY (last_seen, hwadr, ipadr));\n");
  fprintf(f, "CREATE OR REPLACE RULE update_arptable AS\n");
  fprintf(f, "       ON INSERT TO arptable\n");
  fprintf(f, "WHERE (SELECT (now() - '00:05:00'::interval) < max(arptable.last_seen)\n");
  fprintf(f, "       FROM arptable\n");
  fprintf(f, "       WHERE arptable.ipadr = new.ipadr\n");
  fprintf(f, "       AND arptable.hwadr = new.hwadr)\n");
  fprintf(f, "       DO INSTEAD UPDATE arptable SET last_seen = now()\n");
  fprintf(f, "                  WHERE arptable.ipadr = new.ipadr\n");
  fprintf(f, "                  AND arptable.hwadr = new.hwadr\n");
  fprintf(f, "                  AND arptable.last_seen = (SELECT max(arptable.last_seen) AS max\n");
  fprintf(f, "                                            FROM arptable\n");
  fprintf(f, "                                            WHERE arptable.ipadr = new.ipadr\n");
  fprintf(f, "                                            AND arptable.hwadr = new.hwadr);\n\n\n");
  fprintf(f, "You can safely change the table name and the column names, make sure you have configured it correctly then.\n");
};

struct arphdr {
  u_int16_t htype;
  u_int16_t ptype;
  u_char hlen;
  u_char plen;
  u_int16_t oper;
  u_char sha[6];
  u_char spa[4];
  u_char tha[6];
  u_char tpa[4];
};

struct arp_module_config {
  char* table_name;
  char* macaddr_col;
  char* ipaddr_col;
  unsigned int probe_interval;
  unsigned int probe_ranges[MAX_RANGES][2];
  struct connection_struct* database;
};

void* initContext() {
  struct arp_module_config* output = malloc(sizeof(struct arp_module_config));
  output->table_name = "public.arptable";
  output->macaddr_col = "hwadr";
  output->ipaddr_col = "ipadr";
  output->probe_interval = 0;
  memset(output->probe_ranges, 0, sizeof(output->probe_ranges));
  output->database = NULL;
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
  } else if (strcasecmp(key, "probe_interval") == 0)
    arp_config->probe_interval = atoi(value);
  else if (strcasecmp(key, "probe_range") == 0) {
    unsigned int startIp;
    unsigned int endIp;
    if (cidrToIpRange(value, &startIp, &endIp)) {
      int i = 0;
      while (arp_config->probe_ranges[i][0] != 0)
        i++;
      arp_config->probe_ranges[i][0] = startIp;
      arp_config->probe_ranges[i][1] = endIp;
    }
  }
};

struct arping_info {
  int socket;
  struct ifreq interface;
  char* device;
  unsigned char src_ip[4];
  unsigned char src_mac[6];
  struct arp_module_config* arp_config;
};

static void arping_timer(evutil_socket_t fd, short event, void *arg) {
  static const char dst_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  struct arping_info* info = (struct arping_info*) arg;
  static const unsigned int buffer_size = sizeof(struct arphdr) + sizeof(struct ether_header);
  unsigned char buf[buffer_size];
  struct ether_header* eth = (struct ether_header*) buf;
  memcpy(eth->ether_dhost, dst_mac, ETHER_ADDR_LEN);
  memcpy(eth->ether_shost, info->src_mac, ETHER_ADDR_LEN);
  eth->ether_type = htons(ETHERTYPE_ARP);

  struct arphdr *ah = (struct arphdr*) (buf + sizeof(struct ether_header));
  ah->htype = htons(1);
  ah->ptype = htons(0x0800);
  ah->hlen = 6;
  ah->plen = 4;
  ah->oper = htons(ARP_REQUEST);
  memcpy(ah->spa, info->src_ip, 4);
  memcpy(ah->sha, info->src_mac, 6);
  memcpy(ah->tha, dst_mac, 6);
  unsigned int cur_range;
  struct sockaddr addr;
  strncpy(addr.sa_data, info->device, sizeof(addr.sa_data));
  for (cur_range = 0; cur_range < MAX_RANGES; cur_range++) {
    unsigned int startIp = info->arp_config->probe_ranges[cur_range][0];
    if (startIp == 0)
      return;
    unsigned int endIp = info->arp_config->probe_ranges[cur_range][1];
    unsigned int ip;
    for (ip = startIp; ip <= endIp; ip++) {
      ah->tpa[0] = (ip >> 24) & 0xFF;
      ah->tpa[1] = (ip >> 16) & 0xFF;
      ah->tpa[2] = (ip >> 8) & 0xFF;
      ah->tpa[3] = ip & 0xFF;
      sendto(info->socket, buf, sizeof(buf), 0, &addr, sizeof(struct sockaddr));
    }
  }
};

int preCapture(struct event_base* base, char* interface, void* context) {
  struct arp_module_config* arp_config = (struct arp_module_config*) context;
  arp_config->database = initDatabase(base);
  arp_config->database->report_errors = 1;
  arp_config->database->autocommit = 1;
  if (arp_config->probe_interval > 0 && arp_config->probe_ranges[0][0] > 0 && arp_config->probe_ranges[0][1] > 0) {
    struct arping_info* info = malloc(sizeof(struct arping_info));
    info->arp_config = arp_config;
    info->socket = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));
    strcpy(info->interface.ifr_name, interface);
    ioctl(info->socket, SIOCGIFHWADDR, &info->interface);
    memcpy(info->src_mac, info->interface.ifr_hwaddr.sa_data, 6);
    ioctl(info->socket, SIOCGIFADDR, &info->interface);
    memcpy(info->src_ip, (void*) &info->interface.ifr_addr.sa_data + 2, 4);
    info->device = malloc(strlen(interface) + 1);
    strcpy(info->device, interface);
    struct event* timer = event_new(base, -1, EV_PERSIST, arping_timer, info);
    struct timeval tv;
    evutil_timerclear(&tv);
    tv.tv_sec = arp_config->probe_interval;
    tv.tv_usec = 0;
    event_add(timer, &tv);
  }
  return 1;
};

char* getPcapRule(void* context) {
  return "arp";
};

int validateMAC(u_char array[]) {
  if (array[0] == 0x00 && array[1] == 0x00 && array[2] == 0x00
    && array[3] == 0x00 && array[4] == 0x00 && array[5] == 0x00)
    return 0;
  if (array[0] == 0xFF && array[1] == 0xFF && array[2] == 0xFF
    && array[3] == 0xFF && array[4] == 0xFF && array[5] == 0xFF)
    return 0;
  return 1;
};

void rawPacketCallback(const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  struct arphdr *arp = (struct arphdr*) (packet + 14);
  if (ntohs(arp->htype) == 1 && ntohs(arp->ptype) == 0x0800) {
    struct arp_module_config* arp_config = (struct arp_module_config*) context;
    char buf[4096];
    if (arp->spa[0] && validateMAC(arp->sha)) {
      snprintf(buf, sizeof(buf), "INSERT INTO %s (%s, %s) VALUES "
                                "('%02X:%02X:%02X:%02X:%02X:%02X', '%d.%d.%d.%d')"
                                ,arp_config->table_name, arp_config->macaddr_col, arp_config->ipaddr_col
                                ,arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]
                                ,arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
      databaseQuery(arp_config->database, buf, NULL, NULL);
    }
    if (arp->tpa[0] && validateMAC(arp->tha)) {
      snprintf(buf, sizeof(buf), "INSERT INTO %s (%s, %s) VALUES "
                                "('%02X:%02X:%02X:%02X:%02X:%02X', '%d.%d.%d.%d')"
                                ,arp_config->table_name, arp_config->macaddr_col, arp_config->ipaddr_col
                                ,arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]
                                ,arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);
      databaseQuery(arp_config->database, buf, NULL, NULL);
    }
  }
};