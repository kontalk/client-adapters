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

#include "cpim.h"
#include "kontalk.h"

#include <glib.h>
#include <debug.h>
#include <string.h>

#define HEADER_CONTENT_TYPE             "Content-type"
#define MESSAGE_CONTENT_TYPE            "Message/CPIM"
#define TEXT_CONTENT_TYPE               "text/plain"

#define CPIM_MESSAGE_TEMPLATE           \
    HEADER_CONTENT_TYPE ": " MESSAGE_CONTENT_TYPE "\n" \
    "\n" \
    "From: %s\n" \
    "To: %s\n" \
    "DateTime: %s\n" \
    "\n" \
    HEADER_CONTENT_TYPE ": %s%s\n" \
    "\n" \
    "%s"


static char *
readline(char *text, char **next)
{
    char *newline = strchr(text, '\n');
    if (newline != NULL) {
        *newline = '\0';
        *next = newline + 1;
    }
    return text;
}

static char *
parse_header(const char *header, char **name)
{
    char *sep = strchr(header, ':');
    if (sep != NULL) {
        *name = g_strndup(header, sep-header);
        return g_strstrip(g_strdup(sep+1));
    }

    return NULL;
}

void
cpim_message_free(cpim_message *msg)
{
    if (msg != NULL) {
        g_free(msg->from);
        g_free(msg->to);
        g_free(msg->timestamp);
        g_free(msg->type);
        g_free(msg->body);
        g_free(msg);
    }
}

cpim_message *
cpim_parse_message(const char *text, size_t len)
{
    cpim_message *msg = g_malloc0(sizeof(cpim_message));

    char *buf = g_strndup(text, len);
    char *ptr = buf;
    char *key = NULL;
    char *value;
    char *line;
    int parse_ok;

    line = readline(ptr, &ptr);
    value = parse_header(line, &key);

    parse_ok = (value != NULL && !strcasecmp(key, HEADER_CONTENT_TYPE) && !strcasecmp(value, MESSAGE_CONTENT_TYPE));
    g_free((gpointer) value);
    g_free((gpointer) key);

    if (parse_ok) {
        line = readline(ptr, &ptr);
        if (!strlen(g_strstrip(line))) {
            do {
                value = parse_header(line, &key);
                if (value != NULL) {
                    if (!strcasecmp(key, "from")) {
                        msg->from = value;
                    }
                    else if (!strcasecmp(key, "to")) {
                        msg->to = value;
                    }
                    else if (!strcasecmp(key, "datetime")) {
                        msg->timestamp = value;
                    }
                    else {
                        // useless header
                        g_free(value);
                    }

                    g_free(key);
                }
                line = readline(ptr, &ptr);

            } while (strlen(g_strstrip(line)));

            // content type here must be plain text
            line = readline(ptr, &ptr);
            key = NULL;
            value = parse_header(line, &key);
            msg->type = value;

            parse_ok = (value != NULL && !strcasecmp(key, HEADER_CONTENT_TYPE));
            g_free((gpointer) key);

            if (parse_ok) {
                // read the empty line
                line = readline(ptr, &ptr);
                if (!strlen(g_strstrip(line))) {
                    msg->body = g_strdup(ptr);
                }

                return msg;
            }
        }
    }

//fail:
    g_free(buf);
    cpim_message_free(msg);
    return NULL;
}

char *
cpim_message_create_text(const char *body, const char *from, const char *to, const char *timestamp)
{
    return g_strdup_printf(CPIM_MESSAGE_TEMPLATE,
        from,
        to,
        timestamp,
        TEXT_CONTENT_TYPE,
        "; charset=utf-8",
        body);
}
