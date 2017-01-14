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

#include <string.h>
#include <gio/gio.h>
#include <debug.h>

// data key in client connection for getting the connection to the server
#define DATA_RELAY      "connection_relay"
// data key in server (relay) connection for getting the connection to the client
#define DATA_CLIENT     "connection_client"
// data key in server (relay) connection for the TLS connection
#define DATA_TLS        "connection_tls"
// data key for input buffer
#define DATA_BUFFER_IN  "buffer_in"
// data key for output buffer (temporary - will be destroyed when operation is finished)
#define DATA_BUFFER_OUT "buffer_out"

#define BUF_LEN     8192

#define TEXT_INIT       "<?xml version='1.0' ?><stream:stream to='%s' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
#define TEXT_STARTTLS   "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
#define TEXT_SSL_REPLY1 "<proceed xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>"
#define TEXT_SSL_REPLY2 "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
#define TEXT_MECH_EXT   "<mechanism>EXTERNAL</mechanism>"
#define TEXT_MECH_PLAIN "<mechanism>PLAIN</mechanism>"
#define TEXT_PLAIN      "PLAIN"
#define TEXT_EXTERNAL   "EXTERNAL"
#define REGEX_AUTH      "<auth\\s*(.*)\\s*xmlns=['\"]urn:ietf:params:xml:ns:xmpp-sasl['\"](\\s+)mechanism=['\"]PLAIN['\"](.*)>(.*)</auth>$"

static GSocketService *main_service = NULL;
static gchar *relay_service_name = NULL;
static gchar *relay_server_host = NULL;
static guint16 relay_server_port;
static GTlsCertificate *user_certificate = NULL;
static GSocketClient *relay_client = NULL;
// compiled at first usage
static GRegex *auth_regex = NULL;

// https://ubuntuforums.org/showthread.php?t=1309881&p=8216359#post8216359
// adapted for GLib
static gchar *
str_replace(const gchar *orig_str, const gchar *old_token, const gchar *new_token)
{
   gchar *new_str = NULL;
   const gchar* pos = strstr(orig_str, old_token);

   if (pos) {
      new_str = g_malloc0(strlen(orig_str) - strlen(old_token) + strlen(new_token) + 1);

      strncpy(new_str, orig_str, pos - orig_str);
      strcat(new_str, new_token);
      strcat(new_str, pos + strlen(old_token));
   }

   return new_str;
}

static gboolean
regex_match(const gchar *buf, gsize len, const gchar *regex)
{
    if (auth_regex == NULL) {
        GError *err = NULL;
        auth_regex = g_regex_new(REGEX_AUTH, 0, 0, &err);
        if (err != NULL) {
            purple_debug_warning(PACKAGE_NAME, "error compiling regex: %s\n",
                err->message);
            g_error_free(err);
            return FALSE;
        }
    }

    GError *err = NULL;
    GMatchInfo *match = NULL;
    gboolean ret = g_regex_match_full(auth_regex, buf, len, 0, 0, &match, &err);

    if (err != NULL) {
        purple_debug_warning(PACKAGE_NAME, "error matching regex: %s\n",
            err->message);
        g_error_free(err);
        return FALSE;
    }
    if (match != NULL) {
        g_match_info_free(match);
    }

    return ret;
}

static void
relay_read_cb(GInputStream *relay_in, GAsyncResult *res, GSocketConnection *relay_conn);

static void
close_stream(void *stream)
{
    g_io_stream_close(G_IO_STREAM(stream), NULL, NULL);
    g_object_unref(G_OBJECT(stream));
}

static void
stream_write_async(GIOStream *conn, gchar *buf, gsize len, GAsyncReadyCallback callback, gpointer user_data)
{
    GOutputStream *out = g_io_stream_get_output_stream(conn);
    g_assert(out != NULL);

    g_object_set_data(G_OBJECT(out), DATA_BUFFER_OUT, buf);
    g_output_stream_write_all_async(out, buf, len,
        G_PRIORITY_DEFAULT, NULL, callback,
        user_data != NULL ? user_data : conn);
}

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
    // sent data can be destroyed now
    gchar *buf = g_object_get_data(G_OBJECT(relay_out), DATA_BUFFER_OUT);
    g_free(buf);

    GError *err = NULL;
    if (!g_output_stream_write_all_finish(relay_out, res, NULL, &err)) {
        purple_debug_warning(PACKAGE_NAME, "error writing to server: %s\n",
            err->message);
        g_error_free(err);

        // disconnect client
        GSocketConnection *client_conn = g_object_get_data(G_OBJECT(relay_conn), DATA_CLIENT);
        if (client_conn != NULL)
            close_stream(client_conn);

        // disconnect server
        close_stream(relay_conn);
    }
}

static void
client_read_cb(GInputStream *client_in, GAsyncResult *res, GSocketConnection *client_conn)
{
    GSocketConnection *relay_conn = g_object_get_data(G_OBJECT(client_conn), DATA_RELAY);
    if (relay_conn == NULL) {
        // object has been destroyed
        return;
    }

    GError *err = NULL;
    gssize buf_len = g_input_stream_read_finish(client_in, res, &err);

    // error
    if (buf_len < 0) {
        purple_debug_warning(PACKAGE_NAME, "error reading from client: %s\n",
            err->message);
        g_error_free(err);
        // disconnect both sides
        close_stream(relay_conn);
        close_stream(client_conn);
    }
    // connection closed from client
    else if (buf_len == 0) {
        purple_debug_info(PACKAGE_NAME, "connection from client closed.\n");
        // disconnect server
        close_stream(relay_conn);
    }
    else {
        gchar *buf = g_object_get_data(G_OBJECT(client_conn), DATA_BUFFER_IN);
        if (buf != NULL) {
#ifdef DEBUG
            purple_debug_misc(PACKAGE_NAME, "client: \"%.*s\"\n", (int) buf_len, buf);
#endif

            // forward data to server
            GIOStream *tls_relay_conn = g_object_get_data(G_OBJECT(relay_conn), DATA_TLS);
            g_assert(tls_relay_conn != NULL);

            gchar *out;

            // check for PLAIN auth and replace it with EXTERNAL to fool the server
            if (regex_match(buf, buf_len, REGEX_AUTH)) {
                // replace PLAIN with EXTERNAL
                // we are doing string operation so it's better to stringify the buffer
                // TODO this could be avoided by modifying str_replace to accept length
                out = g_memdup(buf, buf_len);
                gchar *buf_str = g_strndup(buf, buf_len);
                gchar *buf_fixed = str_replace(buf_str, TEXT_PLAIN, TEXT_EXTERNAL);
                g_free(buf_str);

                out = buf_fixed;
                buf_len = strlen(buf_fixed);
            }
            else {
                out = g_memdup(buf, buf_len);
            }

            stream_write_async(G_IO_STREAM(tls_relay_conn), out, buf_len, (GAsyncReadyCallback) relay_write_cb, relay_conn);

            // read again
            g_input_stream_read_async(g_io_stream_get_input_stream(G_IO_STREAM(client_conn)),
                buf, BUF_LEN, G_PRIORITY_DEFAULT, NULL, (GAsyncReadyCallback) client_read_cb, client_conn);
        }
    }
}

static void
relay_tls_handshake_cb(GTlsClientConnection *tls_relay_conn, GAsyncResult *res, GSocketConnection *relay_conn)
{
    GSocketConnection *client_conn = g_object_get_data(G_OBJECT(relay_conn), DATA_CLIENT);

    GError *err = NULL;
    if (!g_tls_connection_handshake_finish(G_TLS_CONNECTION(tls_relay_conn), res, &err)) {
        purple_debug_warning(PACKAGE_NAME, "error handshaking TLS with server: %s\n",
            err->message);
        g_error_free(err);

        // disconnect client
        if (client_conn != NULL)
            close_stream(client_conn);

        // disconnect server
        close_stream(relay_conn);

        return;
    }

    purple_debug_misc(PACKAGE_NAME, "TLS handshake with server completed.\n");

    // we got TLS from the relay server
    // now we need to flush out data from the client
    // so start reading from the client socket (i.e. from Pidgin)
    void *client_buf = g_malloc0(BUF_LEN);
    // this will release the buffer on object destruction
    g_object_set_data_full(G_OBJECT(client_conn), DATA_BUFFER_IN, client_buf, g_free);
    g_input_stream_read_async(g_io_stream_get_input_stream(G_IO_STREAM(client_conn)),
        client_buf, BUF_LEN, G_PRIORITY_DEFAULT, NULL, (GAsyncReadyCallback) client_read_cb, client_conn);

    // also resume reading from the server
    void *relay_buf = g_object_get_data(G_OBJECT(relay_conn), DATA_BUFFER_IN);
    g_assert(relay_buf != NULL);
    g_input_stream_read_async(g_io_stream_get_input_stream(G_IO_STREAM(tls_relay_conn)),
        relay_buf, BUF_LEN, G_PRIORITY_DEFAULT, NULL, (GAsyncReadyCallback) relay_read_cb, relay_conn);
}

static void
start_tls(GSocketConnection *relay_conn)
{
    // TODO server identity?
    GTlsClientConnection *tls_relay_conn = G_TLS_CLIENT_CONNECTION
        (g_tls_client_connection_new(G_IO_STREAM(relay_conn), NULL, NULL));
    g_assert(tls_relay_conn != NULL);

    // load client certificate
    g_tls_connection_set_certificate(G_TLS_CONNECTION(tls_relay_conn),
        user_certificate);

    // store our TLS connection object
    g_object_set_data(G_OBJECT(relay_conn), DATA_TLS, tls_relay_conn);

    // start the handshake
    g_tls_client_connection_set_validation_flags(tls_relay_conn,
        G_TLS_CERTIFICATE_UNKNOWN_CA);
    g_tls_connection_handshake_async(G_TLS_CONNECTION(tls_relay_conn),
        G_PRIORITY_DEFAULT, NULL, (GAsyncReadyCallback) relay_tls_handshake_cb, relay_conn);
}

static void
client_write_cb(GOutputStream *client_out, GAsyncResult *res, GSocketConnection *client_conn)
{
    // sent data can be destroyed now
    gchar *buf = g_object_get_data(G_OBJECT(client_out), DATA_BUFFER_OUT);
    g_free(buf);

    GError *err = NULL;
    if (!g_output_stream_write_all_finish(client_out, res, NULL, &err)) {
        purple_debug_warning(PACKAGE_NAME, "error writing to client: %s\n",
            err->message);
        g_error_free(err);

        // disconnect server
        GSocketConnection *relay_conn = g_object_get_data(G_OBJECT(client_conn), DATA_RELAY);
        if (relay_conn != NULL)
            close_stream(relay_conn);

        // disconnect client
        close_stream(client_conn);
    }
}

static void
relay_read_cb(GInputStream *relay_in, GAsyncResult *res, GSocketConnection *relay_conn)
{
    GSocketConnection *client_conn = g_object_get_data(G_OBJECT(relay_conn), DATA_CLIENT);
    if (client_conn == NULL) {
        // object has been destroyed
        return;
    }

    GError *err = NULL;
    gssize buf_len = g_input_stream_read_finish(relay_in, res, &err);

    // error
    if (buf_len < 0) {
        purple_debug_warning(PACKAGE_NAME, "error reading from relay server: %s\n",
            err->message);
        g_error_free(err);
        // disconnect both sides
        close_stream(relay_conn);
        close_stream(client_conn);
    }
    // connection closed from server
    else if (buf_len == 0) {
        purple_debug_info(PACKAGE_NAME, "connection from server closed.\n");
        // disconnect client
        close_stream(client_conn);
    }
    else {
        gchar *buf = g_object_get_data(G_OBJECT(relay_conn), DATA_BUFFER_IN);
        if (buf != NULL) {
#ifdef DEBUG
            purple_debug_misc(PACKAGE_NAME, "server: \"%.*s\"\n", (int) buf_len, buf);
#endif

            GTlsClientConnection *tls_relay_conn = g_object_get_data
                (G_OBJECT(relay_conn), DATA_TLS);

            // in relay mode
            if (tls_relay_conn != NULL) {
                gchar *out;

                // check for EXTERNAL mechanism and replace it with PLAIN to fool Pidgin
                if (memmem(buf, buf_len, TEXT_MECH_EXT, strlen(TEXT_MECH_EXT))) {
                    // replace EXTERNAL with PLAIN
                    // we are doing string operation so it's better to stringify the buffer
                    // TODO this could be avoided by modifying str_replace to accept length
                    gchar *buf_str = g_strndup(buf, buf_len);
                    gchar *buf_fixed = str_replace(buf_str, TEXT_MECH_EXT, TEXT_MECH_PLAIN);
                    g_free(buf_str);

                    out = buf_fixed;
                    buf_len = strlen(buf_fixed);
                }
                else {
                    out = g_memdup(buf, buf_len);
                }

                // forward data to client
                stream_write_async(G_IO_STREAM(client_conn), out, buf_len,
                    (GAsyncReadyCallback) client_write_cb, NULL);

                // read again
                g_input_stream_read_async(g_io_stream_get_input_stream(G_IO_STREAM(tls_relay_conn)),
                    buf, BUF_LEN, G_PRIORITY_DEFAULT, NULL, (GAsyncReadyCallback) relay_read_cb, relay_conn);

            }
            // in autonomous mode
            else {
                // check for starttls proceed command and start TLS against the relay server
                if (memmem(buf, buf_len, TEXT_SSL_REPLY1, strlen(TEXT_SSL_REPLY1)) ||
                    memmem(buf, buf_len, TEXT_SSL_REPLY1, strlen(TEXT_SSL_REPLY2))) {
                    start_tls(relay_conn);
                }
                else {
                    // read again
                    g_input_stream_read_async(g_io_stream_get_input_stream(G_IO_STREAM(relay_conn)),
                        buf, BUF_LEN, G_PRIORITY_DEFAULT, NULL, (GAsyncReadyCallback) relay_read_cb, relay_conn);
                }
            }
        }
    }
}

static void
relay_write_starttls_cb(GOutputStream *relay_out, GAsyncResult *res, GSocketConnection *relay_conn)
{
    // data is static, no need to free

    GError *err = NULL;
    if (!g_output_stream_write_all_finish(relay_out, res, NULL, &err)) {
        purple_debug_warning(PACKAGE_NAME, "error writing to server: %s\n",
            err->message);
        g_error_free(err);

        // disconnect client
        GSocketConnection *client_conn = g_object_get_data(G_OBJECT(relay_conn), DATA_CLIENT);
        if (client_conn != NULL)
            close_stream(client_conn);

        // disconnect server
        close_stream(relay_conn);
    }

    // reading part will catch the "proceed" and start TLS handshake
}

static void
relay_write_init_cb(GOutputStream *relay_out, GAsyncResult *res, GSocketConnection *relay_conn)
{
    // sent data can be destroyed now
    gchar *buf = g_object_get_data(G_OBJECT(relay_out), DATA_BUFFER_OUT);
    g_free(buf);

    GError *err = NULL;
    if (!g_output_stream_write_all_finish(relay_out, res, NULL, &err)) {
        purple_debug_warning(PACKAGE_NAME, "error writing to server: %s\n",
            err->message);
        g_error_free(err);

        // disconnect client
        GSocketConnection *client_conn = g_object_get_data(G_OBJECT(relay_conn), DATA_CLIENT);
        if (client_conn != NULL)
            close_stream(client_conn);

        // disconnect server
        close_stream(relay_conn);
        return;
    }

    // request starttls
    stream_write_async(G_IO_STREAM(relay_conn), TEXT_STARTTLS, strlen(TEXT_STARTTLS),
        (GAsyncReadyCallback) relay_write_starttls_cb, NULL);
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
        close_stream(client_conn);
        return;
    }

    // store a cross-reference to the each other
    g_object_set_data(G_OBJECT(client_conn), DATA_RELAY, relay_conn);
    g_object_set_data(G_OBJECT(relay_conn), DATA_CLIENT, client_conn);

    // start reading from relay connection (connection to server)
    void *relay_buf = g_malloc0(BUF_LEN);
    // this will release the buffer on object destruction
    g_object_set_data_full(G_OBJECT(relay_conn), DATA_BUFFER_IN, relay_buf, g_free);
    g_input_stream_read_async(g_io_stream_get_input_stream(G_IO_STREAM(relay_conn)),
        relay_buf, BUF_LEN, G_PRIORITY_DEFAULT, NULL, (GAsyncReadyCallback) relay_read_cb, relay_conn);

    // begin communication with server
    gchar *init_out = g_strdup_printf(TEXT_INIT, relay_service_name);
    stream_write_async(G_IO_STREAM(relay_conn), init_out, strlen(init_out),
        (GAsyncReadyCallback) relay_write_init_cb, NULL);
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

static gboolean
load_client_certificate(const gchar *cert_file, const gchar *key_file, GError **error)
{
    user_certificate = g_tls_certificate_new_from_files(cert_file, key_file, error);
    return user_certificate != NULL;
}

TunnelError
tunnel_start(guint16 listen_port, const gchar *service_name,
    const gchar *server_host, guint16 server_port,
    const gchar* cert_file, const gchar *key_file)
{
    if (cert_file == NULL || key_file == NULL) {
        // configuration error
        return TUN_ERR_CONFIG;
    }

    GError *err = NULL;

    // load certificate
    if (!load_client_certificate(cert_file, key_file, &err)) {
        purple_debug_warning(PACKAGE_NAME, "unable to load client certificate: %s\n",
            err->message);
        g_error_free(err);
        return TUN_ERR_CERTIFICATE;
    }

    main_service = g_socket_service_new();
    g_assert(main_service != NULL);
    relay_client = g_socket_client_new();
    g_assert(relay_client != NULL);
    // client event handler is global so connect it now
    g_signal_connect(G_OBJECT(relay_client), "event", G_CALLBACK(client_event), NULL);

    if (!g_socket_listener_add_inet_port(G_SOCKET_LISTENER(main_service), listen_port, NULL, &err)) {
        purple_debug_warning(PACKAGE_NAME, "unable to listen on port %d: %s\n",
            listen_port, err->message);
        g_error_free(err);
        return TUN_ERR_LISTEN;
    }

    g_signal_connect(G_OBJECT(main_service), "incoming", G_CALLBACK(socket_incoming), NULL);
    relay_service_name = g_strdup(service_name);
    relay_server_host = g_strdup(server_host);
    relay_server_port = server_port;
    return TUN_ERR_OK;
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
        relay_server_host = NULL;
        g_free(relay_service_name);
        relay_service_name = NULL;
        main_service = NULL;
    }
}
