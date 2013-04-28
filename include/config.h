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

#include <pcap.h>
#include <event2/event.h>

typedef void* init_function();
typedef void parseconfig_function(char* key, char* value, void* context);
typedef char* pcaprule_function();
typedef void pcap_packet_callback(const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context);

struct config {
  char* interface;
  struct module* modules;
  struct config* next;
};

struct module {
  void* mod_handle;
  void* context;
  pcap_t *pcap_handle;
  pcap_packet_callback *packet_callback;
  struct module* next;
};

int parse_config(char* config_file);

int launch_config(struct event_base* base);

#endif //_CONFIG_H