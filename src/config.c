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

#include <stdio.h>
#include <errno.h>
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
  struct interface* interface = NULL;
  while (fgets(line_buffer, sizeof(line_buffer), f)) {
    if (strlen(line_buffer) == 1)
      continue;
    char key[MAXLINE];
    char value[MAXLINE];
    if (sscanf(line_buffer, "%[a-z] = %s", &key, &value) == 2) {
      if (strcasecmp(key, "interface") == 0) {
        int sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sd > 0) {
          interface = malloc(sizeof(struct interface));
          interface->interface = malloc(strlen(value) + 1);
          strcpy(interface->interface, value);
          struct ifreq ifr;
          memset (&ifr, 0, sizeof (ifr));
          snprintf(ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface->interface);
          if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
            fprintf(stderr, "Error '%s' for interface '%s'\n", strerror(errno), value);
            fclose(f);
            return 1;
          }
          int i;
          for (i = 0; i < 6; i++)
            interface->mac_addr[i] = ifr.ifr_hwaddr.sa_data[i];
          close(sd);
          struct config* node = config;
          while (node->next != NULL)
            node = node->next;
          node->interface = interface;
        } else {
          fprintf(stderr, "Error '%s' for interface '%s'\n", strerror(errno), value);
          fclose(f);
          return 1;
        }
      } else if (strcasecmp(key, "range") == 0) {
        interface->range = malloc(strlen(value) + 1);
        strcpy(interface->range, value);
        printf("Range for %s is %s\n", interface->interface, interface->range);
        printf("Mac address for %s is %02x:%02x:%02x:%02x:%02x:%02x\n", interface->interface
              ,interface->mac_addr[0], interface->mac_addr[1], interface->mac_addr[2], interface->mac_addr[3]
              ,interface->mac_addr[4], interface->mac_addr[5]);
      }
    } else {
      fprintf(stderr, "There was an error while parsing the following line\n%s", line_buffer);
      fclose(f);
      return 0;
    }
  }
  fclose(f);
  return 0;
};