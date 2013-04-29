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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <event2/event.h>

char* getPcapRule(void* context) {
  return "arp";
};

#define ARP_REQUEST 1
#define ARP_REPLY 2

typedef struct arphdr {
  u_int16_t htype;
  u_int16_t ptype;
  u_char hlen;
  u_char plen;
  u_int16_t oper;
  u_char sha[6];
  u_char spa[4];
  u_char tha[6];
  u_char tpa[4];
} arphdr_t;

void rawPacketCallback(const unsigned char *packet, struct pcap_pkthdr pkthdr, void* context) {
  arphdr_t *arpheader = (struct arphdr*) (packet + 14);
  if ((arpheader->tha[0] == 0x00 && arpheader->tha[1] == 0x00 && arpheader->tha[2] == 0x00
      && arpheader->tha[3] == 0x00 && arpheader->tha[4] == 0x00 && arpheader->tha[5] == 0x00)
      || (arpheader->tha[0] == 0xFF && arpheader->tha[1] == 0xFF && arpheader->tha[2] == 0xFF
      && arpheader->tha[3] == 0xFF && arpheader->tha[4] == 0xFF && arpheader->tha[5] == 0xFF))
    return;
  if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) {
    int i;
    printf("Sender MAC: ");
    for (i = 0; i < 6; i++)
      printf("%02X%s", arpheader->sha[i], (i != 5) ? ":" : "");
    printf("\nSender IP: ");
    for (i = 0; i < 4; i++)
      printf("%d%s", arpheader->spa[i], (i != 3) ? "." : "");
    printf("\nTarget MAC: ");
    for(i = 0; i < 6; i++)
      printf("%02X%s", arpheader->tha[i], (i != 5) ? ":" : "");
    printf("\nTarget IP: ");
    for(i = 0; i < 4; i++)
      printf("%d%s", arpheader->tpa[i], (i != 3) ? "." : "");
    printf("\n");
  }
};