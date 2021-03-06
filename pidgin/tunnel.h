/*
 * Kontalk Pidgin plugin
 * Copyright (C) 2017 Kontalk Devteam <devteam@kontalk.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _TUNNEL_H_
#define _TUNNEL_H_

#include <glib.h>

typedef enum {
    TUN_ERR_OK = 0,
    TUN_ERR_LISTEN,
    TUN_ERR_CERTIFICATE,
    TUN_ERR_CONFIG,
} TunnelError;

TunnelError
tunnel_start(guint16 listen_port, const gchar *service_name,
    const gchar *server_host, guint16 server_port,
    const gchar* cert_file, const gchar *key_file);


void tunnel_stop();

#endif  /* _TUNNEL_H_ */
