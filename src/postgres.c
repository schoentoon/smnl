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

#include "postgres.h"

#include <event2/bufferevent.h>
#include <event2/event_struct.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

struct query_struct {
  void (*callback)(PGresult*,void*,char*);
  void *context;
  char *query;
  unsigned char sent : 1;
  struct query_struct *next;
};

static struct database_list {
  struct connection_struct* db;
  struct database_list* next;
} *all_databases;

char* db_connect = "";

static void pq_event(evutil_socket_t fd, short event, void *arg);
static int highPriorityDatabaseQuery(struct connection_struct* conn, char* query, void (*callback)(PGresult*,void*,char*), void* context);

struct connection_struct* initDatabase(struct event_base* base) {
  struct connection_struct* database = malloc(sizeof(struct connection_struct));
  database->query_count = 0;
  database->report_errors = 0;
  database->queries = NULL;
  database->last_query = NULL;
  database->conn = PQconnectdb(db_connect);
  if (PQstatus(database->conn) != CONNECTION_OK) {
    fprintf(stderr, "%s\n", PQerrorMessage(database->conn));
    PQfinish(database->conn);
    exit(1);
  } else
    PQsetnonblocking(database->conn, 1);
  struct event* event = event_new(base, PQsocket(database->conn), EV_READ|EV_PERSIST, pq_event, database);
  event_add(event, NULL);
  if (all_databases == NULL) {
    all_databases = malloc(sizeof(struct database_list));
    memset(all_databases, 0, sizeof(struct database_list));
    all_databases->db = database;
  } else {
    struct database_list* node = all_databases;
    while (node->next)
      node = node->next;
    node->next = malloc(sizeof(struct database_list));
    memset(node->next, 0, sizeof(struct database_list));
    node->next->db = database;
  }
  return database;
};

void enable_autocommit(struct connection_struct* conn) {
  if (!conn)
    return;
  highPriorityDatabaseQuery(conn, "SET AUTOCOMMIT = ON", NULL, NULL);
};

void dispatchDatabases() {
  struct database_list* node = all_databases;
  while (node) {
    pq_event(0, 0, node->db);
    node = node->next;
  };
};

static void pq_event(evutil_socket_t fd, short event, void *arg) {
  struct connection_struct* database = (struct connection_struct*) arg;
  if (database->queries) {
    if (database->queries->sent == 0) {
      PQsendQuery(database->conn, database->queries->query);
      database->queries->sent = 1;
    }
    if (PQconsumeInput(database->conn) && !PQisBusy(database->conn)) {
      PGresult* res = PQgetResult(database->conn);
      while (res) {
        if (database->queries->callback)
          database->queries->callback(res, database->queries->context, database->queries->query);
        if (database->report_errors && PQresultStatus(res) != PGRES_COMMAND_OK)
          fprintf(stderr, "Query: '%s' returned error\n\t%s\n", database->queries->query, PQresultErrorMessage(res));
        PQclear(res);
        res = PQgetResult(database->conn);
      }
      database->query_count--;
      struct query_struct* old = database->queries;
      database->queries = database->queries->next;
      free(old->query);
      free(old);
      pq_event(fd, event, arg);
    }
  }
}

void appendQueryPool(struct connection_struct* conn, struct query_struct* query) {
  if (conn->query_count == 0 || !conn->last_query) {
    conn->queries = query;
    conn->last_query = query;
    conn->query_count++;
    pq_event(0, 0, conn);
  } else {
    conn->last_query->next = query;
    conn->last_query = query;
    conn->query_count++;
  }
}

static int highPriorityDatabaseQuery(struct connection_struct* conn, char* query, void (*callback)(PGresult*,void*,char*), void* context) {
  if (query == NULL || conn == NULL)
    return 0;
  struct query_struct* query_struct = malloc(sizeof(struct query_struct));
  if (query_struct == NULL)
    return 0;
  query_struct->query = malloc(strlen(query) + 1);
  strcpy(query_struct->query, query);
  query_struct->callback = callback;
  query_struct->context = context;
  query_struct->sent = 0;
  query_struct->next = NULL;
  if (conn->query_count == 0) {
    conn->queries = query_struct;
    conn->query_count++;
    pq_event(0, 0, conn);
  } else {
    query_struct->next = conn->queries;
    conn->queries = query_struct;
    conn->query_count++;
  }
  return 1;
};

int databaseQuery(struct connection_struct* conn, char* query, void (*callback)(PGresult*,void*,char*), void* context) {
  if (query == NULL || conn == NULL)
    return 0;
  struct query_struct* query_struct = malloc(sizeof(struct query_struct));
  if (query_struct == NULL)
    return 0;
  query_struct->query = malloc(strlen(query) + 1);
  strcpy(query_struct->query, query);
  query_struct->callback = callback;
  query_struct->context = context;
  query_struct->sent = 0;
  query_struct->next = NULL;
  appendQueryPool(conn, query_struct);
  return 1;
}