#define PURPLE_PLUGINS

#include <glib.h>

#include "notify.h"
#include "gtkplugin.h"
#include "version.h"

static gboolean
plugin_load(PurplePlugin *plugin) {
    purple_notify_message(plugin, PURPLE_NOTIFY_MSG_INFO, "Hello World!",
                        "This is the Hello World! plugin :)", NULL, NULL, NULL);

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
