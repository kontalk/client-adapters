#define PURPLE_PLUGINS

#include <glib.h>
#include <glib/gi18n.h>

#include <notify.h>
#include <gtkblist.h>
#include <gtkplugin.h>
#include <debug.h>
#include <version.h>

#include "kontalk.h"
#include "gpg.h"


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

static void
xmlnode_replace_data(xmlnode *node, const char *text, size_t len)
{
    xmlnode *c;

    for(c = node->child; c; c = c->next) {
        if(c->type == XMLNODE_TYPE_DATA) {
            g_free(c->data);
            c->data = (char *) text;
            c->data_sz = len;
            break;
        }
    }
}

static gboolean
jabber_iq_received(PurpleConnection *pc, const char *type, const char *id,
                   const char *from, xmlnode *iq)
{
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
                        purple_debug_warning(PACKAGE_NAME, "error importing public key for %s\n",
                            from);
                    }
                    else {
                        purple_debug_misc(PACKAGE_NAME, "public key for %s imported (fingerprint %s)\n",
                            from, fingerprint ? fingerprint : "(null)");
                    }
                }
            }

            g_free((gpointer) keydata);

            // packet was processed
            return TRUE;
        }

        // continue processing
        return FALSE;
}

static gboolean
jabber_message_received(PurpleConnection *pc, const char *type, const char *id,
                        const char *from, const char *to, xmlnode *message)
{
    purple_debug_misc(PACKAGE_NAME, "jabber message (type=%s, id=%s, "
        "from=%s to=%s) %p\n",
        type ? type : "(null)", id ? id : "(null)",
        from ? from : "(null)", to ? to : "(null)", message);

    xmlnode *e2e, *body;
    if (from != NULL && !g_strcmp0(type, "chat") &&
        (e2e = xmlnode_get_child_with_namespace(message, E2E_ELEMENT, E2E_NAMESPACE)) != NULL) {

        // extract and decode e2e content
        char *data = xmlnode_get_data(e2e);
        if (data != NULL && *(g_strchomp(data)) != '\0') {
            size_t len, out_len;
            g_base64_decode_inplace(data, &len);

            if (len > 0) {
                // decrypt!
                char *text = (char *) gpg_decrypt((void *) data, len, &out_len);
                if (text != NULL && (body = xmlnode_get_child(message, "body")) != NULL) {
                    purple_debug_misc(PACKAGE_NAME, "replacing message body \"%s\" with:\n%s",
                        body->data, text);

                    // inject into body
                    // WARNING accessing xmlnode internals
                    xmlnode_replace_data(body, text, out_len);
                }
            }
        }

        g_free(data);
    }

    // continue processing
    return FALSE;
}

static gboolean
jabber_presence_received(PurpleConnection *pc, const char *type,
                         const char *from, xmlnode *presence)
{
    if (from != NULL) {
        // store fingerprint regardless of presence type
        char* fingerprint = NULL;
        xmlnode *pubkey = xmlnode_get_child_with_namespace(presence, PUBKEY_ELEMENT, PUBKEY_NAMESPACE);
        if (pubkey != NULL) {
            xmlnode *fpr_node = xmlnode_get_child(pubkey, "print");
            if (fpr_node != NULL) {
                fingerprint = xmlnode_get_data(fpr_node);
                if (fingerprint != NULL && *(g_strchomp(fingerprint)) != '\0') {
                    purple_debug_misc(PACKAGE_NAME, "public key fingerprint for %s: %s\n",
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
                        purple_debug_warning(PACKAGE_NAME, "buddy %s not found!\n", from);
                    }

                }

                g_free((gpointer) fingerprint);
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
        purple_notify_message(plugin, PURPLE_NOTIFY_MSG_ERROR, PACKAGE_TITLE,
            // TODO i18n
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
        purple_signal_connect(jabber_handle, "jabber-receiving-message",
            plugin, PURPLE_CALLBACK(jabber_message_received), NULL);

        purple_signal_connect(pidgin_blist_get_handle(), "drawing-tooltip",
            plugin, PURPLE_CALLBACK(append_to_tooltip), NULL);

        // TODO warn once
        purple_notify_message(plugin, PURPLE_NOTIFY_MSG_INFO, PACKAGE_TITLE,
            // TODO i18n
            "You need to use the SSL tunnel bridge!", NULL, NULL, NULL);

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

    PLUGIN_ID,
    NULL,
    PACKAGE_VERSION,

    NULL,
    NULL,
    PLUGIN_AUTHOR,
    PLUGIN_WEBSITE,

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
#ifdef ENABLE_NLS
    bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
#endif /* ENABLE_NLS */

    info.name = _("Kontalk integration");
    info.summary = _("Provides support for features used by a Kontalk server.");
    info.description = _("Provides support for encryption, key management, media exchange,"
        " registration and authentication for a Kontalk server");
}

PURPLE_INIT_PLUGIN(kontalk, init_plugin, info)
