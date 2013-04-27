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

#include <getopt.h>
#include <event2/event.h>

static const struct option g_LongOpts[] = {
  { "help",     no_argument,       0, 'h' },
  { "config",   required_argument, 0, 'C' },
  { 0, 0, 0, 0 }
};

int usage(char* program) {
  fprintf(stderr, "USAGE: %s [options]\n", program);
  fprintf(stderr, "-h, --help\tShow this help.\n");
  fprintf(stderr, "-C, --config\tUse this configuration file.\n");
  return 0;
};

int main(int argc, char** argv) {
  int iArg, iOptIndex = -1;
  while ((iArg = getopt_long(argc, argv, "hC:", g_LongOpts, &iOptIndex)) != -1) {
    switch (iArg) {
      case 'C':
        if (parse_config(optarg) == 0)
          return 1;
        break;
      default:
      case 'h':
        return usage(argv[0]);
    }
  }
  struct event_base* event_base = event_base_new();
  initDatabasePool(event_base, "");
  return 0;
};