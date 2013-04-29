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

#ifndef _HEADERS_H
#define _HEADERS_H

#include <arpa/inet.h>

#define ETHER_ADDR_LEN  6
#define SIZE_ETHERNET 14
#define SIZE_FRAGMENT_HDR 8
#define SIZE_UDP 8
#define IPv4_ETHERTYPE 0x800
#define IPv6_ETHERTYPE 0x86DD
#define UDP 17

struct ethernet_header {
  uint8_t       ether_dhost[ETHER_ADDR_LEN];    /* Destination host address */
  uint8_t       ether_shost[ETHER_ADDR_LEN];    /* Source host address */
  uint16_t      ether_type;                     /* IP? ARP? RARP? etc */
};

struct ipv4_header {
  uint8_t               ip_vhl;     /* version << 4 | header length >> 2 */
  uint8_t               ip_tos;     /* type of service */
  uint16_t              ip_len;     /* total length */
  uint16_t              ip_id;      /* identification */
  uint16_t              ip_off;     /* fragment offset field */
#define IP_RF 0x8000                /* reserved fragment flag */
#define IP_DF 0x4000                /* dont fragment flag */
#define IP_MF 0x2000                /* more fragments flag */
#define IP_OFFMASK 0x1fff           /* mask for fragmenting bits */
  uint8_t               ip_ttl;     /* time to live */
  uint8_t               ip_p;       /* protocol */
  uint16_t              ip_sum;     /* checksum */
  struct in_addr        ip_src, ip_dst;     /* source and dest address */
};

struct udp_header {
  uint16_t      sport;      /* source port */
  uint16_t      dport;      /* destination port */
  uint16_t      udp_length;
  uint16_t      udp_sum;    /* checksum */
};

char getIpVersion(const unsigned char *packet);

struct ipv4_header* getIPv4Header(const unsigned char *packet);

struct udp_header* getUDPHeaderFromIPv4(const unsigned char *packet, struct ipv4_header* ipv4);

#endif //_HEADERS