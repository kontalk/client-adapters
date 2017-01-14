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

#ifndef _KONTALK_H_
#define _KONTALK_H_

// this is not translatable
#define PACKAGE_TITLE           "Kontalk"

#define PLUGIN_ID               "gtk-" PACKAGE_NAME
#define PLUGIN_AUTHOR           "Kontalk devteam <devteam@kontalk.org>"
#define PLUGIN_WEBSITE          "http://www.kontalk.org/"

#define PUBKEY_ELEMENT          "pubkey"
#define PUBKEY_NAMESPACE        "urn:xmpp:pubkey:2"

#define DEFAULT_TUNNEL_PORT     5224
#define DEFAULT_RELAY_HOST      "beta.kontalk.net"
#define DEFAULT_RELAY_PORT      5222

#define E2E_ELEMENT             "e2e"
#define E2E_NAMESPACE           "urn:ietf:params:xml:ns:xmpp-e2e"

#define XMPP_CONTENT_TYPE       "application/xmpp+xml"
#define XMPP_ELEMENT            "xmpp"
#define XMPP_NAMESPACE          "jabber:client"

#endif  /* _KONTALK_H_ */
