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
  Table for this module sort of looks like this
  CREATE TABLE public.arptable (
   hwadr macaddr,
   ipadr inet,
   PRIMARY KEY (hwadr, ipadr));
 */

#define ARP_REQUEST 1
#define ARP_REPLY 2

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

#define MAX_RANGES 256

struct arp_module_config {
  char* table_name;
  char* macaddr_col;
  char* ipaddr_col;
  unsigned int probe_interval;
  unsigned int probe_ranges[MAX_RANGES][2];
};

void* initContext() {
  struct arp_module_config* output = malloc(sizeof(struct arp_module_config));
  output->table_name = "public.arptable";
  output->macaddr_col = "hwadr";
  output->ipaddr_col = "ipadr";
  output->probe_interval = 0;
  memset(output->probe_ranges, 0, sizeof(output->probe_ranges));
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
    fprintf(stderr, "device %s\n", info->device);
    fprintf(stderr, "mac %02X:%02X:%02X:%02X:%02X:%02X\n", info->src_mac[0], info->src_mac[1], info->src_mac[2], info->src_mac[3], info->src_mac[4], info->src_mac[5]);
    fprintf(stderr, "ip %d.%d.%d.%d\n", info->src_ip[0], info->src_ip[1], info->src_ip[2], info->src_ip[3]);
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

void queryCallback(PGresult* res, void* context, char* query) {
  if (PQresultStatus(res) != PGRES_COMMAND_OK)
    fprintf(stderr, "Query: '%s' returned error\n\t%s\n", query, PQresultErrorMessage(res));
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
      snprintf(buf, sizeof(buf), "BEGIN;INSERT INTO %s (%s, %s) VALUES "
                                "('%02X:%02X:%02X:%02X:%02X:%02X', '%d.%d.%d.%d');COMMIT;"
                                ,arp_config->table_name, arp_config->macaddr_col, arp_config->ipaddr_col
                                ,arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]
                                ,arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
      databaseQuery(buf, queryCallback, NULL);
    }
    if (arp->tpa[0] && validateMAC(arp->tha)) {
      snprintf(buf, sizeof(buf), "BEGIN;INSERT INTO %s (%s, %s) VALUES "
                                "('%02X:%02X:%02X:%02X:%02X:%02X', '%d.%d.%d.%d');COMMIT;"
                                ,arp_config->table_name, arp_config->macaddr_col, arp_config->ipaddr_col
                                ,arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]
                                ,arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);
      databaseQuery(buf, queryCallback, NULL);
    }
  }
};