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

#include <math.h>
#include <string.h>
#include <stdlib.h>

unsigned int ip2ui(char *ip) {
  long ipAsUInt = 0;
  char *cPtr = strtok(ip, ".");
  if(cPtr)
    ipAsUInt += atoi(cPtr) * pow(256, 3);
  int exponent = 2;
  while(cPtr && exponent >= 0) {
    cPtr = strtok(NULL, ".\0");
    if(cPtr)
      ipAsUInt += atoi(cPtr) * pow(256, exponent--);
  }
  return ipAsUInt;
}

unsigned int createBitmask(const char *bitmask) {
  unsigned int times = (unsigned int) atol(bitmask) - 1;
  unsigned int i;
  unsigned int bitmaskAsUInt = 1;
  for (i = 0; i < times; ++i) {
    bitmaskAsUInt <<= 1;
    bitmaskAsUInt |= 1;
  }
  for(i = 0; i < 32 - times - 1; ++i)
    bitmaskAsUInt <<= 1;
  return bitmaskAsUInt;
}

int cidrToIpRange(char* cidr, unsigned int *startIp, unsigned int *endIp) {
  char* ip = strtok(cidr, "/");
  if (!ip)
    return 0;
  char* bitmask = strtok(NULL, "\0");
  if (!bitmask)
    return 0;
  unsigned int ipAsUInt = ip2ui(ip);
  unsigned int bitmaskAsUInt = createBitmask(bitmask);
  *startIp = (ipAsUInt & bitmaskAsUInt) + 1; /* We don't want to have a x.x.x.0 ip address.. */
  *endIp = (ipAsUInt | ~bitmaskAsUInt) - 1; /* We don't want a x.x.x.255 ip address either.. */
  return 1;
};