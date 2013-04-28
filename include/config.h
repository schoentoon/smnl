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

typedef void* init_function();
typedef void parseconfig_function(char* key, char* value, void* context);
typedef char* pcaprule_function();

struct config {
  struct interface* interface;
  struct module* modules;
  struct config* next;
};

struct module {
  void* mod_handle;
  void* context;
  struct module* next;
};

static struct config* config;

struct interface {
  char* interface;
  char* range;
  unsigned char mac_addr[6];
};

int parse_config(char* config_file);

#endif //_CONFIG_H