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

#include <stdio.h>

char getIpVersion(const unsigned char *packet) {
  struct ethernet_header *ethernet = (struct ethernet_header*) packet;
  if (ntohs(ethernet->ether_type) == IPv6_ETHERTYPE)
    return 6;
  else if (ntohs(ethernet->ether_type) == IPv4_ETHERTYPE)
    return 4;
  return 0;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IPV4_VERSION(ip) (((ip)->ip_vhl) >> 4)

struct ethernet_header* getEthernetHeader(const unsigned char *packet) {
  return (struct ethernet_header*) packet;
};

struct ipv4_header* getIPv4Header(const unsigned char *packet) {
  if (getIpVersion(packet) == 4) {
    struct ipv4_header* output = (struct ipv4_header*) (packet + SIZE_ETHERNET);
    if (IPV4_VERSION(output) == 4)
      return output;
  }
  return NULL;
};

struct udp_header* getUDPHeaderFromIPv4(const unsigned char *packet, struct ipv4_header* ipv4) {
  if (ipv4->ip_p == UDP)
    return (struct udp_header*) (packet + SIZE_ETHERNET + (IP_HL(ipv4) * 4));
  return NULL;
};
