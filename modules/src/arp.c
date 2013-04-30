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

struct arping_info {
  int socket;
  struct ifreq interface;
  char* device;
  char src_ip[4];
  char src_mac[6];
};

static void arping_timer(evutil_socket_t fd, short event, void *arg) {
  static const char dst_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  struct arping_info* info = (struct arping_info*) arg;
  unsigned int buffer_size = sizeof(struct arphdr) + sizeof(struct ether_header);
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
  memcpy(info->src_ip, ah->spa, 4);
  memcpy(info->src_mac, ah->sha, 6);
  memcpy(ah->tha, dst_mac, 6);
  ah->tpa[0] = 192;
  ah->tpa[1] = 168;
  ah->tpa[2] = 0;
  struct sockaddr addr;
  strncpy(addr.sa_data, info->device, sizeof(addr.sa_data));
  int i;
  for (i = 1; i < 255; i++) {
    ah->tpa[3] = i;
    sendto(info->socket, buf, sizeof(buf), 0, &addr, sizeof(struct sockaddr));
  }
};

int preCapture(struct event_base* base, char* interface, void* context) {
  struct arping_info* info = malloc(sizeof(struct arping_info));
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
  tv.tv_sec = 5;
  tv.tv_usec = 0;
  event_add(timer, &tv);
  return 1;
};

char* getPcapRule(void* context) {
  return "arp";
};

void queryCallback(PGresult* res, void* context, char* query) {
  if (PQresultStatus(res) != PGRES_COMMAND_OK)
    fprintf(stderr, "Query: '%s' returned error\n\t%s\n", query, PQresultErrorMessage(res));
};

void rawPacketCallback(const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  struct arphdr *arp = (struct arphdr*) (packet + 14);
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