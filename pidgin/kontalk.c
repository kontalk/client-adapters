#define PURPLE_PLUGINS

#include <glib.h>
#include <glib/gi18n.h>

#include <notify.h>
#include <gtkblist.h>
#include <gtkplugin.h>
#include <debug.h>
#include <version.h>


#define PUBKEY_ELEMENT          "pubkey"
#define PUBKEY_NAMESPACE        "urn:xmpp:pubkey:2"


static void
append_to_tooltip(PurpleBlistNode *node, GString *text, gboolean full)
{
    if (full) {
        const gchar *note = purple_blist_node_get_string(node, "fingerprint");

        if ((note != NULL) && (*note != '\0')) {
            char *tmp, *esc;
            purple_markup_html_to_xhtml(note, NULL, &tmp);
            esc = g_markup_escape_text(tmp, -1);
            g_free(tmp);
            g_string_append_printf(text, _("\n<b>Fingerprint</b>: %s"), esc);
            g_free(esc);
        }
    }
}

static gboolean
jabber_presence_received(PurpleConnection *pc, const char *type,
                         const char *from, xmlnode *presence)
{
        //purple_debug_misc("kontalk", "jabber presence (type=%s, from=%s) %p\n",
        //    type ? type : "(null)", from ? from : "(null)", presence);

        if (from != NULL) {
            // store fingerprint regardless of presence type
            char* fingerprint = NULL;
            xmlnode *pubkey = xmlnode_get_child_with_namespace(presence, PUBKEY_ELEMENT, PUBKEY_NAMESPACE);
            if (pubkey != NULL) {
                xmlnode *fpr_node = xmlnode_get_child(pubkey, "print");
                if (fpr_node != NULL) {
                    fingerprint = xmlnode_get_data(fpr_node);
                    if (fingerprint != NULL && *(g_strchomp(fingerprint)) != '\0') {
                        purple_debug_misc("kontalk", "public key fingerprint for %s: %s\n",
                            from, fingerprint);

                        // retrieve buddy from name
                        PurpleBuddy *buddy = purple_find_buddy(pc->account, from);
                        if (buddy != NULL) {
                            // store fingerprint
                            purple_blist_node_set_string(&buddy->node, "fingerprint", fingerprint);
                        }
                        else {
                            purple_debug_misc("kontalk", "buddy %s not found!\n", from);
                        }

                        g_free((gpointer) fingerprint);
                    }
                }
            }
        }

        // continue with processing
        return FALSE;
}

static gboolean
plugin_load(PurplePlugin *plugin) {
    /*purple_notify_message(plugin, PURPLE_NOTIFY_MSG_INFO, "Kontalk",
                        "This is the Kontalk plugin :)", NULL, NULL, NULL);*/

    void *jabber_handle   = purple_plugins_find_with_id("prpl-jabber");

    if (jabber_handle) {
        purple_signal_connect(jabber_handle, "jabber-receiving-presence",
            plugin, PURPLE_CALLBACK(jabber_presence_received), NULL);

        purple_signal_connect(pidgin_blist_get_handle(), "drawing-tooltip",
            plugin, PURPLE_CALLBACK(append_to_tooltip), NULL);

        return TRUE;
    }

    return FALSE;
}

static PurplePluginInfo info = {
    PURPLE_PLUGIN_MAGIC,
    PURPLE_MAJOR_VERSION,
    PURPLE_MINOR_VERSION,
    PURPLE_PLUGIN_STANDARD,
    PIDGIN_PLUGIN_TYPE,
    0,
    NULL,
    PURPLE_PRIORITY_DEFAULT,

    "gtk-kontalk",
    "Kontalk integration",
    "0.1",

    "Provides support for features used by a Kontalk server.",
    "Provides support for encryption, key management, media exchange,"
        " registration and authentication for a Kontalk server",
    "Kontalk devteam <devteam@kontalk.org>",
    "http://www.kontalk.org",

    plugin_load,
    NULL,
    NULL,

    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static void
init_plugin(PurplePlugin *plugin)
{
}

PURPLE_INIT_PLUGIN(kontalk, init_plugin, info)
