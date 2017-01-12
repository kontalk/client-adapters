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

#include "tunnel.h"

#include <gio/gio.h>
#include <debug.h>

// data key in client connection for getting the connection to the server
#define DATA_RELAY  "relay"
// data key in server (relay) connection for getting the connection to the client
#define DATA_CLIENT "client"

#define BUF_LEN     8192

static GSocketService *main_service = NULL;
static gchar *relay_server_host = NULL;
static guint16 relay_server_port;
static GSocketClient *relay_client = NULL;

static void
client_event(GSocketClient *client, GSocketClientEvent event, GSocketConnectable *connectable,
    GIOStream *connection, gpointer user_data)
{
    // TODO
    purple_debug_misc(PACKAGE_NAME, "relay connection event: %d\n", event);
}

static void
relay_write_cb(GOutputStream *relay_out, GAsyncResult *res, GSocketConnection *relay_conn)
{
    GError *err = NULL;
    if (!g_output_stream_write_all_finish(relay_out, res, NULL, &err)) {
        purple_debug_warning(PACKAGE_NAME, "error writing to server: %s\n",
            err->message);
        g_error_free(err);
        // TODO we should close both connections now
    }
}

static gboolean
client_channel_read(GIOChannel *client_channel, GIOCondition cond, GSocketConnection *client_conn)
{
    GSocketConnection *relay_conn = g_object_get_data(G_OBJECT(client_conn), DATA_RELAY);
    if (relay_conn == NULL) {
        // object has been destroyed
        return FALSE;
    }

    gchar *buf = g_malloc0(BUF_LEN);
    gsize buf_len = 0;
    GError *err = NULL;
    GIOStatus ret = g_io_channel_read_chars(client_channel, buf, BUF_LEN, &buf_len, &err);
    if (ret != G_IO_STATUS_NORMAL) {
        if (err != NULL) {
            purple_debug_info(PACKAGE_NAME, "error reading from client: %s\n",
                err->message);
            g_error_free(err);
        }
        else if (ret == G_IO_STATUS_EOF) {
            purple_debug_info(PACKAGE_NAME, "connection from client closed.\n");
        }

        // close connection to the server
        g_io_stream_close(G_IO_STREAM(relay_conn), NULL, NULL);
        g_object_unref(relay_conn);
        // close connection to the client
        g_io_stream_close(G_IO_STREAM(client_conn), NULL, NULL);
        g_object_unref(client_conn);

        return FALSE;
    }

    purple_debug_misc(PACKAGE_NAME, "client: \"%s\"\n", buf);
    // relay data to the server
    GOutputStream *relay_out = g_io_stream_get_output_stream(G_IO_STREAM(relay_conn));
    g_output_stream_write_all_async(relay_out, buf, buf_len, G_PRIORITY_DEFAULT,
        NULL, (GAsyncReadyCallback) relay_write_cb, relay_conn);
    // FIXME memory leak on buf

    return TRUE;
}

static void
client_write_cb(GOutputStream *client_out, GAsyncResult *res, GSocketConnection *client_conn)
{
    GError *err = NULL;
    if (!g_output_stream_write_all_finish(client_out, res, NULL, &err)) {
        purple_debug_warning(PACKAGE_NAME, "error writing to client: %s\n",
            err->message);
        g_error_free(err);
        // TODO we should close both connections now
    }
}

static gboolean
relay_channel_read(GIOChannel *relay_channel, GIOCondition cond, GSocketConnection *relay_conn)
{
    GSocketConnection *client_conn = g_object_get_data(G_OBJECT(relay_conn), DATA_CLIENT);
    if (client_conn == NULL) {
        // object has been destroyed
        return FALSE;
    }

    gchar *buf = g_malloc0(BUF_LEN);
    gsize buf_len = 0;
    GError *err = NULL;
    GIOStatus ret = g_io_channel_read_chars(relay_channel, buf, BUF_LEN, &buf_len, &err);
    if (ret != G_IO_STATUS_NORMAL) {
        if (err != NULL) {
            purple_debug_info(PACKAGE_NAME, "error reading from server: %s\n",
                err->message);
            g_error_free(err);
        }
        else if (ret == G_IO_STATUS_EOF) {
            purple_debug_info(PACKAGE_NAME, "connection from server closed.\n");
        }

        // close connection to the server
        g_io_stream_close(G_IO_STREAM(relay_conn), NULL, NULL);
        g_object_unref(relay_conn);
        // close connection to the client
        g_io_stream_close(G_IO_STREAM(client_conn), NULL, NULL);
        g_object_unref(client_conn);

        return FALSE;
    }

    // TODO check for starttls proceed command and start TLS against the relay server

    purple_debug_misc(PACKAGE_NAME, "server: \"%s\"\n", buf);
    // relay data to the client
    GOutputStream *client_out = g_io_stream_get_output_stream(G_IO_STREAM(client_conn));
    g_output_stream_write_all_async(client_out, buf, buf_len, G_PRIORITY_DEFAULT,
        NULL, (GAsyncReadyCallback) client_write_cb, client_conn);
    // FIXME memory leak on buf

    return TRUE;
}

/**
 * Callback for relay server connection event.
 * @param connection the connection from Pidgin
 */
static void
relay_connected_cb(GSocketClient *client, GAsyncResult *res, GSocketConnection *client_conn)
{
    GError *err = NULL;
    GSocketConnection *relay_conn = g_socket_client_connect_to_host_finish(client, res, &err);
    if (relay_conn == NULL) {
        purple_debug_warning(PACKAGE_NAME, "unable to connect to relay server: %s\n",
            err->message);
        g_error_free(err);

        // close connection from Pidgin
        g_io_stream_close(G_IO_STREAM(client_conn), NULL, NULL);
    }

    // we'll need the client connection to be destroyed when the service connection is dropped
    g_object_set_data(G_OBJECT(client_conn), DATA_RELAY, relay_conn);
    g_object_set_data(G_OBJECT(relay_conn), DATA_CLIENT, client_conn);

    // channel I/O for client connection (connection from Pidgin)
    GSocket *client_socket = g_socket_connection_get_socket(client_conn);
    gint client_fd = g_socket_get_fd(client_socket);
    GIOChannel *client_channel = g_io_channel_unix_new(client_fd);
    g_io_add_watch(client_channel, G_IO_IN, (GIOFunc) client_channel_read, client_conn);

    // channel I/O for relay connection (connection to server)
    GSocket *relay_socket = g_socket_connection_get_socket(relay_conn);
    gint relay_fd = g_socket_get_fd(relay_socket);
    GIOChannel *relay_channel = g_io_channel_unix_new(relay_fd);
    g_io_add_watch(relay_channel, G_IO_IN, (GIOFunc) relay_channel_read, relay_conn);
}

static gboolean
connect_to_relay_server(GSocketConnection *connection)
{
    g_socket_client_connect_to_host_async(relay_client, relay_server_host, relay_server_port,
        NULL, (GAsyncReadyCallback) relay_connected_cb, connection);
    return TRUE;
}

static gboolean
socket_incoming(GSocketService *service, GSocketConnection *connection, GObject *source_object, gpointer user_data)
{
    GSocketAddress *addr = g_socket_connection_get_remote_address(connection, NULL);
    g_assert(addr != NULL);

    gchar *addr_str = g_socket_connectable_to_string(G_SOCKET_CONNECTABLE(addr));
    purple_debug_info(PACKAGE_NAME, "incoming connection from %s\n", addr_str);
    g_free(addr_str);

    // we intend to use our connection object
    g_object_ref(connection);

    // connect to the relay server and go on
    connect_to_relay_server(connection);
    return TRUE;
}

gboolean
tunnel_start(guint16 listen_port, const gchar *server_host, guint16 server_port)
{
    main_service = g_socket_service_new();
    g_assert(main_service != NULL);
    relay_client = g_socket_client_new();
    g_assert(relay_client != NULL);
    // client event handler is global so connect it now
    g_signal_connect(G_OBJECT(relay_client), "event", G_CALLBACK(client_event), NULL);

    GError *err = NULL;
    if (!g_socket_listener_add_inet_port(G_SOCKET_LISTENER(main_service), listen_port, NULL, &err)) {
        purple_debug_warning(PACKAGE_NAME, "unable to listen on port %d: %s\n",
            listen_port, err->message);
        g_error_free(err);
        return FALSE;
    }

    g_signal_connect(G_OBJECT(main_service), "incoming", G_CALLBACK(socket_incoming), NULL);
    relay_server_host = g_strdup(server_host);
    relay_server_port = server_port;
    return TRUE;
}

void
tunnel_stop()
{
    if (main_service != NULL) {
        g_socket_service_stop(main_service);
        g_socket_listener_close(G_SOCKET_LISTENER(main_service));
        g_object_unref(main_service);
        g_object_unref(relay_client);
        g_free(relay_server_host);
        main_service = NULL;
    }
}
