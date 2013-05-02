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

#ifndef _POSTGRES_H
#define _POSTGRES_H

#include <event2/event.h>

#define MAX_CONNECTIONS 10
#define MAX_IDLE_TICKS 100000

#include <libpq-fe.h>

char* db_connect;

struct connection_struct {
  PGconn *conn;
  struct query_struct *queries;
  unsigned int query_count;
  unsigned int idle_ticker;
  unsigned char autocommit;
  unsigned char since_last_commit;
  unsigned char report_errors : 1;
};

/** Initialize our database pool
 * @param base The event_base used for our internal timer
 * @return Basically your private database connection
 */
struct connection_struct* initDatabase(struct event_base* base);

/** Execute a query on our database pool
 * @param conn The database connection to launch the query on
 * @param query The query to execute
 * @param callback The function to call after our query is done
 * @param context A pointer to pass to your callback
 * @return 1 in case the query was valid and put onto our database pool
 */
int databaseQuery(struct connection_struct* conn, char* query, void (*callback)(PGresult*,void*,char*), void* context);

void dispatchDatabases();

#endif //_POSTGRES_H