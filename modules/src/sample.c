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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct test {
  char* testvar;
};

void* initContext() {
  fprintf(stderr, "initContext();\n");
  return malloc(sizeof(struct test));
};

void parseConfig(char* key, char* value, void* context) {
  fprintf(stderr, "parseConfig('%s', '%s', %p);\n", key, value, context);
  if (strcmp(key, "test") == 0) {
    fprintf(stderr, "Value is %s.\n", value);
    struct test* ctx = (struct test*) context;
    ctx->testvar = malloc(strlen(value) + 1);
    strcpy(ctx->testvar, value);
  }
};

char* getPcapRule() {
  fprintf(stderr, "getPcapRule();\n");
  return "arp";
};