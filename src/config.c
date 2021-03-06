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

char* offline_file = NULL;

int parse_config(char* config_file) {
  FILE* f = fopen(config_file, "r");
  if (f == NULL) {
    fprintf(stderr, "Error '%s' while opening '%s'.\n", strerror(errno), config_file);
    return 0;
  }
  char line_buffer[BUFSIZ];
  config = malloc(sizeof(struct config));
  memset(config, 0, sizeof(struct config));
  struct module* module = NULL;
  struct config* current_config = config;
  unsigned int line_count = 0;
  while (fgets(line_buffer, sizeof(line_buffer), f)) {
    line_count++;
    if (strlen(line_buffer) == 1 || line_buffer[0] == '#')
      continue;
    char key[MAXLINE];
    char value[MAXLINE];
    if (sscanf(line_buffer, "%[a-z_] = %[^\t\n]", &key, &value) == 2) {
      if (strcasecmp(key, "dbconnect") == 0)
        db_connect = strdup(value);
      else if (strcasecmp(key, "interface") == 0) {
        if (current_config->interface) {
          current_config->next = malloc(sizeof(struct config));
          memset(current_config->next, 0, sizeof(struct config));
          current_config = current_config->next;
        }
        current_config->interface = strdup(value);
      } else if (strcasecmp(key, "load_module") == 0) {
        if (current_config->interface == NULL) {
          fprintf(stderr, "Error on line %zd\t", line_count);
          fprintf(stderr, "Missing the interface key, this has to be defined before loading modules.\n");
          return 0;
        }
        void* mod_handle = dlopen(value, RTLD_LAZY);
        if (mod_handle) {
          module = malloc(sizeof(struct module));
          memset(module, 0, sizeof(struct module));
          module->mod_handle = mod_handle;
          if (dlsym(mod_handle, "getPcapRule") == NULL) {
            fprintf(stderr, "Error on line %zd\t", line_count);
            fprintf(stderr, "Error: %s\n", dlerror());
            fprintf(stderr, "Module '%s' doesn't seem to have the function getPcapRule(), which is required.\n", value);
            fclose(f);
            return 0;
          } else {
            module->rawpacket_callback = dlsym(mod_handle, "rawPacketCallback");
            module->ipv4_callback = dlsym(mod_handle, "IPv4Callback");
            module->ipv4_udp_callback = dlsym(mod_handle, "IPv4UDPCallback");
            if (!(module->rawpacket_callback || module-> ipv4_callback || module->ipv4_udp_callback)) {
              fprintf(stderr, "Error on line %zd\t", line_count);
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
          fprintf(stderr, "Error on line %zd\t", line_count);
          fprintf(stderr, "There was an error while loading module '%s'.\n", dlerror());
          fclose(f);
          return 0;
        }
      } else if (module && module->mod_handle) {
        parseconfig_function* parse_config = dlsym(module->mod_handle, "parseConfig");
        if (parse_config)
          parse_config(key, value, module->context);
        else {
          fprintf(stderr, "Warning on line %zd\t", line_count);
          fprintf(stderr, "You specified a value for this module, but this module doesn't accept additional options.\n");
        }
      }
    } else {
      fprintf(stderr, "Error on line %zd\t", line_count);
      fprintf(stderr, "There was an error while parsing this line.\n", line_buffer);
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
  const unsigned char *packet = NULL;
  while ((packet = pcap_next(mod->pcap_handle, &pkthdr)) != NULL) {
    dispatchDatabases();
    if (mod->rawpacket_callback)
      mod->rawpacket_callback(packet, pkthdr, mod->context);
    struct ethernet_header* ethernet_header = NULL;
    struct ipv4_header* ipv4 = NULL;
    if (mod->ipv4_callback) {
      ethernet_header = getEthernetHeader(packet);
      ipv4 = getIPv4Header(packet);
      if (ethernet_header && ipv4)
        mod->ipv4_callback(ethernet_header, ipv4, packet, pkthdr, mod->context);
    }
    if (mod->ipv4_udp_callback) {
      if (!ethernet_header)
        ethernet_header = getEthernetHeader(packet);
      if (!ipv4)
        ipv4 = getIPv4Header(packet);
      if (ethernet_header && ipv4) {
        struct udp_header* udp = getUDPHeaderFromIPv4(packet, ipv4);
        if (udp)
          mod->ipv4_udp_callback(ethernet_header, ipv4, udp, packet, pkthdr, mod->context);
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
        if (offline_file) {
          if ((mod->pcap_handle = pcap_open_offline(offline_file, errbuf)) == NULL) {
            fprintf(stderr, "ERROR: %s\n", errbuf);
            exit(1);
          }
        } else {
          if ((mod->pcap_handle = pcap_open_live(config_node->interface, BUFSIZ, 0, 512, errbuf)) == NULL) {
            fprintf(stderr, "ERROR: %s\n", errbuf);
            exit(1);
          } else if (pcap_lookupnet(config_node->interface, &netaddr, &mask, errbuf) == -1) {
            fprintf(stderr, "ERROR: %s\n", errbuf);
            exit(1);
          }
        }
      }
      pcaprule_function* rule_func = dlsym(mod->mod_handle, "getPcapRule");
      if (rule_func == NULL) {
        fprintf(stderr, "ERROR: %s\n", dlerror());
        exit(1);
      } else if (pcap_compile(mod->pcap_handle, &filter, rule_func(mod->context), 1, mask) == -1) {
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(mod->pcap_handle));
        exit(1);
      } else if (pcap_setfilter(mod->pcap_handle, &filter) == -1) {
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(mod->pcap_handle));
        exit(1);
      } else {
        if (offline_file) {
          pcap_callback(0, 0, mod);
        } else {
          struct event* ev = event_new(base, pcap_fileno(mod->pcap_handle), EV_READ|EV_PERSIST, pcap_callback, mod);
          event_add(ev, NULL);
        }
      }
      mod = mod->next;
    }
    config_node = config_node->next;
  }
  return 1;
};

void showStats(int signal) {
  struct config* config_node = config;
  while (config_node) {
    struct module* mod = config_node->modules;
    while (mod) {
      struct pcap_stat stats;
      if (pcap_stats(mod->pcap_handle, &stats) == 0) {
        fprintf(stderr, "Received %u packets.\n", stats.ps_recv);
        fprintf(stderr, "Dropped %u packets.\n", stats.ps_drop);
      };
      mod = mod->next;
    };
    config_node = config_node->next;
  };
};