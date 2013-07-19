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

#ifndef _CONFIG_H
#define _CONFIG_H

#include "headers.h"

#include <pcap.h>
#include <event2/event.h>

typedef void* init_function();
typedef void parseconfig_function(char* key, char* value, void* context);
typedef char* pcaprule_function(void* context);
typedef void sql_schema_function(FILE* f);
typedef int pre_capture_function(struct event_base* base, char* interface, void* context);
typedef void pcap_rawpacket_callback(const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context);
typedef void pcap_ipv4_callback(struct ethernet_header* ethernet, struct ipv4_header* ipv4, const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context);
typedef void pcap_ipv4_udp_callback(struct ethernet_header* ethernet, struct ipv4_header* ipv4, struct udp_header* udp, const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context);

char* offline_file;

struct config {
  char* interface;
  struct module* modules;
  struct config* next;
};

struct module {
  void* mod_handle;
  void* context;
  pcap_t *pcap_handle;
  pcap_rawpacket_callback *rawpacket_callback;
  pcap_ipv4_callback      *ipv4_callback;
  pcap_ipv4_udp_callback  *ipv4_udp_callback;
  struct module* next;
};

int parse_config(char* config_file);

int launch_config(struct event_base* base);

void showStats(int signal);

#endif //_CONFIG_H