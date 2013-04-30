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

#include "config.h"
#include "postgres.h"

#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bits/ioctls.h>

#define MAXLINE 4096

static struct config* config = NULL;

int parse_config(char* config_file) {
  FILE* f = fopen(config_file, "r");
  if (f == NULL) {
    fprintf(stderr, "Error '%s' while opening '%s'.\n", strerror(errno), config_file);
    return 0;
  }
  char line_buffer[BUFSIZ];
  config = malloc(sizeof(struct config));
  struct module* module = NULL;
  struct config* current_config = config;
  while (fgets(line_buffer, sizeof(line_buffer), f)) {
    if (strlen(line_buffer) == 1 || line_buffer[0] == '#')
      continue;
    char key[MAXLINE];
    char value[MAXLINE];
    if (sscanf(line_buffer, "%[a-z_] = %[^\t\n]", &key, &value) == 2) {
      if (strcasecmp(key, "dbconnect") == 0) {
        db_connect = malloc(strlen(value) + 1);
        strcpy(db_connect, value);
      } else if (strcasecmp(key, "interface") == 0) {
        if (current_config->interface) {
          current_config->next = malloc(sizeof(struct config));
          current_config = current_config->next;
        }
        current_config->interface = malloc(strlen(value) + 1);
        strcpy(current_config->interface, value);
      } else if (strcasecmp(key, "load_module") == 0) {
        if (current_config->interface == NULL) {
          fprintf(stderr, "Missing the interface key, this has to be defined before loading modules.\n");
          return 0;
        }
        void* mod_handle = dlopen(value, RTLD_LAZY);
        if (mod_handle) {
          module = malloc(sizeof(struct module));
          module->mod_handle = mod_handle;
          if (dlsym(mod_handle, "getPcapRule") == NULL) {
            fprintf(stderr, "Module '%s' doesn't seem to have the function getPcapRule(), which is required.\n", value);
            fclose(f);
            return 0;
          } else {
            module->rawpacket_callback = dlsym(mod_handle, "rawPacketCallback");
            module->ipv4_callback = dlsym(mod_handle, "IPv4Callback");
            module->ipv4_udp_callback = dlsym(mod_handle, "IPv4UDPCallback");
            if (module->rawpacket_callback || module-> ipv4_callback || module->ipv4_udp_callback) {
            } else {
              fprintf(stderr, "Module '%s' doesn't seem to have a callback function, which is required.\n", value);
              fclose(f);
              return 0;
            }
          }
          init_function *init = dlsym(mod_handle, "initContext");
          if (init)
            module->context = (*init)();
          struct module* node = current_config->modules;
          if (node == NULL)
            current_config->modules = module;
          else {
            while (node->next)
              node = node->next;
            node->next = module;
          }
        } else {
          fprintf(stderr, "There was an error while loading module '%s'.\n", dlerror());
          fclose(f);
          return 0;
        }
      } else if (module) {
        parseconfig_function* parse_config = dlsym(module->mod_handle, "parseConfig");
        if (parse_config)
          parse_config(key, value, module->context);
        else
          fprintf(stderr, "You specified a value for this module, but this module doesn't accept additional options.\n");
      }
    } else {
      fprintf(stderr, "There was an error while parsing the following line\n%s", line_buffer);
      fclose(f);
      return 0;
    }
  }
  fclose(f);
  return 1;
};

void pcap_callback(evutil_socket_t fd, short what, void *arg) {
  struct module* mod = (struct module*) arg;
  struct pcap_pkthdr pkthdr;
  const unsigned char *packet=NULL;
  while ((packet = pcap_next(mod->pcap_handle, &pkthdr)) != NULL) {
    if (mod->rawpacket_callback)
      mod->rawpacket_callback(packet, pkthdr, mod->context);
    struct ipv4_header* ipv4 = NULL;
    if (mod->ipv4_callback) {
      ipv4 = getIPv4Header(packet);
      if (ipv4)
        mod->ipv4_callback(ipv4, packet, pkthdr, mod->context);
    }
    if (mod->ipv4_udp_callback) {
      if (!ipv4)
        ipv4 = getIPv4Header(packet);
      if (ipv4) {
        struct udp_header* udp = getUDPHeaderFromIPv4(packet, ipv4);
        if (udp)
          mod->ipv4_udp_callback(ipv4, udp, mod->context);
      }
    }
  }
};

int launch_config(struct event_base* base) {
  bpf_u_int32 netaddr = 0, mask = 0;
  struct bpf_program filter;
  char errbuf[PCAP_ERRBUF_SIZE];
  memset(errbuf, 0, PCAP_ERRBUF_SIZE);
  struct config* config_node = config;
  while (config_node) {
    struct module* mod = config_node->modules;
    while (mod) {
      pre_capture_function* precapture_func = dlsym(mod->mod_handle, "preCapture");
      if ((precapture_func && precapture_func(base, config_node->interface, mod->context)) || precapture_func == NULL) {
        if ((mod->pcap_handle = pcap_open_live(config_node->interface, BUFSIZ, 0,  512, errbuf)) == NULL)
          fprintf(stderr, "ERROR: %s\n", errbuf);
        else if (pcap_lookupnet(config_node->interface, &netaddr, &mask, errbuf) == -1)
          fprintf(stderr, "ERROR: %s\n", errbuf);
        else {
          pcaprule_function* rule_func = dlsym(mod->mod_handle, "getPcapRule");
          if (pcap_compile(mod->pcap_handle, &filter, rule_func(mod->context), 1, mask) == -1)
            fprintf(stderr, "ERROR: %s\n", pcap_geterr(mod->pcap_handle));
          else if (pcap_setfilter(mod->pcap_handle, &filter) == -1)
            fprintf(stderr, "ERROR: %s\n", pcap_geterr(mod->pcap_handle));
          else {
            struct event* ev = event_new(base, pcap_fileno(mod->pcap_handle), EV_READ|EV_PERSIST, pcap_callback, mod);
            event_add(ev, NULL);
          }
        }
      }
      mod = mod->next;
    }
    config_node = config_node->next;
  }
  return 1;
};