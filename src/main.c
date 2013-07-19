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

#include <dlfcn.h>
#include <getopt.h>
#include <signal.h>

#include <event2/event.h>

static const struct option g_LongOpts[] = {
  { "help",       no_argument,       0, 'h' },
  { "config",     required_argument, 0, 'C' },
  { "test-config",required_argument, 0, 'T' },
  { "sql-schema", required_argument, 0, 'S' },
  { "file",       required_argument, 0, 'f' },
  { 0, 0, 0, 0 }
};

int usage(char* program) {
  fprintf(stderr, "USAGE: %s [options]\n", program);
  fprintf(stderr, "-h, --help\tShow this help.\n");
  fprintf(stderr, "-C, --config\tUse this configuration file.\n");
  fprintf(stderr, "-f, --file\tUse this file instead of actual data.\n");
  fprintf(stderr, "-T, --test-config\tTest the configuration file.\n");
  fprintf(stderr, "-S, --sql-schema\tShow the sql schema assumed by this module.\n");
  return 0;
};

int main(int argc, char** argv) {
  int iArg, iOptIndex = -1;
  while ((iArg = getopt_long(argc, argv, "hC:T:S:f:", g_LongOpts, &iOptIndex)) != -1) {
    switch (iArg) {
      case 'f':
        offline_file = optarg;
        break;
      case 'T':
        if (parse_config(optarg) == 0)
          return 1;
        fprintf(stderr, "Config file seems to be fine.\n");
        return 0;
      case 'C':
        if (parse_config(optarg) == 0)
          return 1;
        break;
      case 'S': {
        void* mod_handle = dlopen(optarg, RTLD_LAZY);
        if (mod_handle) {
          sql_schema_function *sql_schema = dlsym(mod_handle, "printSQLSchema");
          if (sql_schema)
            sql_schema(stderr);
          else
            fprintf(stderr, "Error: '%s'\n", dlerror());
        } else
          fprintf(stderr, "Error: '%s'\n", dlerror());
        return 0;
      }
      default:
      case 'h':
        return usage(argv[0]);
    }
  }
  struct event_base* event_base = event_base_new();
  launch_config(event_base);
  if (offline_file)
    return 0;
  signal(SIGUSR1, showStats);
  while (1)
    event_base_dispatch(event_base);
  return 0;
};