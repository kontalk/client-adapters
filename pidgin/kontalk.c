#define PURPLE_PLUGINS

#include <glib.h>
#include <glib/gi18n.h>

#include <notify.h>
#include <gtkblist.h>
#include <gtkplugin.h>
#include <debug.h>
#include <version.h>

#include "gpg.h"

#define PUBKEY_ELEMENT          "pubkey"
#define PUBKEY_NAMESPACE        "urn:xmpp:pubkey:2"


static char *
jabber_get_bare_jid(const char *in)
{
    if (in != NULL) {
        char *out = g_strdup(in);
        char *sep = strstr(out, "/");
        if (sep != NULL) {
            *sep = '\0';
        }
        return out;
    }

    return NULL;
}

static char*
generate_next_id()
{
    static guint32 index = 0;

    if (index == 0) {
        do {
            index = g_random_int();
        } while (index == 0);
    }

    return g_strdup_printf("purpledisco%x", index++);
}

static void
request_public_key(PurpleConnection *pc, const char *jid)
{
    char *id = generate_next_id();

    xmlnode *iq = xmlnode_new("iq");
    xmlnode_set_attrib(iq, "type", "get");
    xmlnode_set_attrib(iq, "to", jid);
    xmlnode_set_attrib(iq, "id", id);
    g_free(id);

    xmlnode *pubkey = xmlnode_new_child(iq, PUBKEY_ELEMENT);
    xmlnode_set_namespace(pubkey, PUBKEY_NAMESPACE);

    purple_signal_emit(purple_connection_get_prpl(pc), "jabber-sending-xmlnode",
        pc, &iq);

    xmlnode_free(iq);
}

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
jabber_iq_received(PurpleConnection *pc, const char *type, const char *id,
                   const char *from, xmlnode *iq)
{
        //purple_debug_misc("kontalk", "jabber IQ (type=%s, id=%s, from=%s) %p\n",
        //    type, id, from ? from : "(null)", iq);

        xmlnode *pubkey;
        if (from != NULL && !g_strcmp0(type, "result") &&
            (pubkey = xmlnode_get_child_with_namespace(iq, PUBKEY_ELEMENT, PUBKEY_NAMESPACE)) != NULL) {

            // just import the key for now
            char* keydata = xmlnode_get_data(pubkey);
            if (keydata != NULL && *(g_strchomp(keydata)) != '\0') {
                size_t len;
                g_base64_decode_inplace(keydata, &len);

                if (len > 0) {
                    const char* fingerprint = gpg_import_key((void*) keydata, len);
                    if (fingerprint == NULL) {
                        purple_debug_warning("kontalk", "error importing public key for %s\n",
                            from);
                    }
                    else {
                        purple_debug_misc("kontalk", "public key for %s imported (fingerprint %s)\n",
                            from, fingerprint ? fingerprint : "(null)");
                    }

                    // packet was processed
                    return TRUE;
                }
            }
        }

        // continue processing
        return FALSE;
}

static gboolean
jabber_presence_received(PurpleConnection *pc, const char *type,
                         const char *from, xmlnode *presence)
{
    /*
     * TODO this should probably be enabled only for Kontalk accounts,
     * but for that to work we need a protocol plugin.
     */
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
                        // is the fingerprint changed?
                        const char* old_fingerprint = purple_blist_node_get_string
                            (&buddy->node, "fingerprint");

                        if (g_strcmp0(old_fingerprint, fingerprint)) {
                            // fingerprint changed, request key
                            char* jid = jabber_get_bare_jid(from);
                            request_public_key(pc, jid);
                            g_free(jid);
                        }

                        // store fingerprint
                        purple_blist_node_set_string(&buddy->node, "fingerprint", fingerprint);
                    }
                    else {
                        purple_debug_warning("kontalk", "buddy %s not found!\n", from);
                    }

                    g_free((gpointer) fingerprint);
                }
            }
        }
    }

    // continue processing
    return FALSE;
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
    // init gpgme
    if (!gpg_init()) {
        // TODO i18n
        purple_notify_message(plugin, PURPLE_NOTIFY_MSG_ERROR, "Kontalk",
                    "GPGME >= " GPGME_REQUIRED_VERSION " is required.", NULL, NULL, NULL);
        return FALSE;
    }

    void *jabber_handle = purple_plugins_find_with_id("prpl-jabber");

    if (jabber_handle) {
        // init signals
        purple_signal_connect(jabber_handle, "jabber-receiving-presence",
            plugin, PURPLE_CALLBACK(jabber_presence_received), NULL);
        // TODO convert to jabber-register-namespace-watcher?
        purple_signal_connect(jabber_handle, "jabber-receiving-iq",
            plugin, PURPLE_CALLBACK(jabber_iq_received), NULL);

        purple_signal_connect(pidgin_blist_get_handle(), "drawing-tooltip",
            plugin, PURPLE_CALLBACK(append_to_tooltip), NULL);

        return TRUE;
    }

    return FALSE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
    purple_signals_disconnect_by_handle(plugin);
    gpg_free();

    return TRUE;
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
    "http://www.kontalk.org/",

    plugin_load,
    plugin_unload,
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
