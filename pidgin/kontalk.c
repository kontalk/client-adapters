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
#include "cpim.h"


#define SECRET_KEY_PREF         "/plugins/gtk/" PACKAGE_NAME "/secret_key"


static char *
extract_oob_url(xmlnode *message)
{
    xmlnode *oob = xmlnode_get_child_with_namespace(message, "x", "jabber:x:oob");
    if (oob != NULL) {
        xmlnode *url = xmlnode_get_child(oob, "url");
        if (url != NULL) {
            return xmlnode_get_data(url);
        }
    }

    return NULL;
}

static xmlnode *
parse_xmpp_stanza(const char *text, gssize size)
{
    xmlnode *child = NULL;
    xmlnode *doc = xmlnode_from_str(text, size);
    if (doc != NULL &&
        !strcmp(doc->name, XMPP_ELEMENT) &&
        !strcmp(xmlnode_get_namespace(doc), XMPP_NAMESPACE)) {

        child = doc->child;
        while (child != NULL) {
            if (child->name != NULL) {
                child = xmlnode_copy(child);
                break;
            }
            child = child->next;
        }
    }

    if (doc != NULL) {
        xmlnode_free(doc);
    }

    return child;
}

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

    return g_strdup_printf("purple%x", index++);
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
            size_t text_len = (len == -1) ? strlen(text) : len;
            c->data = g_memdup(text, text_len);
            c->data_sz = text_len;
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
                char *text = gpg_decrypt((void *) data, len, &out_len);
                if (text != NULL && (body = xmlnode_get_child(message, "body")) != NULL) {
                    char *body_text, *url = NULL;
                    size_t body_len;

                    // parse Message/CPIM
                    cpim_message *msg = cpim_parse_message(text, out_len);
                    if (msg != NULL) {
                        // TODO check security status
                        body_text = msg->body;
                        body_len = strlen(msg->body);

                        if (msg->type != NULL && g_str_has_prefix(msg->type, XMPP_CONTENT_TYPE)) {
                            xmlnode *stanza = parse_xmpp_stanza(body_text, body_len);
                            if (stanza != NULL && !strcmp(stanza->name, "message")) {
                                // look for out-of-band
                                url = extract_oob_url(stanza);
                                if (url != NULL) {
                                    body_text = url;
                                    body_len = strlen(url);
                                }
                            }
                        }
                    }
                    else {
                        body_text = text;
                        body_len = out_len;
                    }

                    // inject into body
                    // WARNING accessing xmlnode internals
                    xmlnode_replace_data(body, body_text, body_len);

                    // free cpim data
                    cpim_message_free(msg);
                    // free url
                    free(url);
                }

                gpg_data_free(text);
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

static xmlnode *
create_encryption_node(const char *cipher, size_t cipher_len)
{
    xmlnode *node = xmlnode_new(E2E_ELEMENT);
    xmlnode_set_namespace(node, E2E_NAMESPACE);

    // encode data
    char *encoded = g_base64_encode((unsigned char *) cipher, cipher_len);
    if (encoded) {
        xmlnode_insert_data(node, encoded, -1);
        return node;
    }

    xmlnode_free(node);
    return NULL;
}

static gboolean
jabber_xmlnode_sending(PurpleConnection *pc, xmlnode **packet)
{
    xmlnode *body;
    char *cpim, *text;
    const char *to;
    char *cipher;
    const char *fingerprint = NULL;
    size_t cipher_len;

    // create CPIM message from body node
    if (!strcmp((*packet)->name, "message") && (body = xmlnode_get_child(*packet, "body")) != NULL) {
        to = xmlnode_get_attrib(*packet, "to");

        // retrieve fingerprint for user
        PurpleBuddy *buddy = purple_find_buddy(pc->account, to);
        if (buddy != NULL) {
            // is the fingerprint changed?
            fingerprint = purple_blist_node_get_string
                (&buddy->node, "fingerprint");

            if (fingerprint == NULL) {
                purple_debug_warning(PACKAGE_NAME, "buddy %s has no fingerprint!\n", to);
                return FALSE;
            }
        }
        else {
            purple_debug_warning(PACKAGE_NAME, "buddy %s not found!\n", to);
            return FALSE;
        }

        if (fingerprint != NULL) {
            text = xmlnode_get_data(body);

            char *jid = jabber_get_bare_jid(to);
            char *sender = jabber_get_bare_jid(pc->account->username);
            cpim = cpim_message_create_text(text, sender, jid, "2015-02-05T19:00:00+00:00");
            purple_debug_misc(PACKAGE_NAME, "CPIM DATA for %s:\n%s\n", to, cpim);
            g_free(jid);
            g_free(sender);
            free(text);

            if (!gpg_encrypt(fingerprint, purple_prefs_get_string(SECRET_KEY_PREF), cpim, strlen(cpim), &cipher, &cipher_len)) {
                xmlnode *child = create_encryption_node(cipher, cipher_len);
                gpg_data_free(cipher);

                if (child != NULL) {
                    // replace body with a dummy
                    // WARNING accessing xmlnode internals
                    xmlnode_replace_data(body, _("(encrypted)"), -1);
                    // add the encrypted part
                    xmlnode_insert_child(*packet, child);
                }
            }

            g_free(cpim);
        }
    }

    // continue processing
    return FALSE;
}

static PurplePluginPrefFrame *
pref_frame(PurplePlugin *plugin)
{
    PurplePluginPrefFrame *frame = purple_plugin_pref_frame_new();
    PurplePluginPref *pref =
        purple_plugin_pref_new_with_name_and_label(SECRET_KEY_PREF,
            _("Secret key"));

    purple_plugin_pref_frame_add(frame, pref);

    return frame;
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
        //purple_signal_connect(jabber_handle, "jabber-sending-xmlnode",
        //    plugin, PURPLE_CALLBACK(jabber_xmlnode_sending), NULL);

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

static PurplePluginUiInfo prefs_info = {
        pref_frame,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
};

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
    &prefs_info,
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

    purple_prefs_add_none("/plugins");
    purple_prefs_add_none("/plugins/gtk");
    purple_prefs_add_none("/plugins/gtk/" PACKAGE_NAME);

    purple_prefs_add_string(SECRET_KEY_PREF, "");

}

PURPLE_INIT_PLUGIN(kontalk, init_plugin, info)
