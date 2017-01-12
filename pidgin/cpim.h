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

#ifndef _CPIM_H_
#define _CPIM_H_

#include <stddef.h>

typedef struct {
    char *from;
    char *to;
    char *timestamp;
    char *type;

    char *body;
} cpim_message;

void cpim_message_free(cpim_message *msg);

cpim_message *cpim_parse_message(const char *text, size_t len);

char *cpim_message_create_text(const char *body, const char *from, const char *to, const char *timestamp);

#endif  /* _CPIM_H_ */
