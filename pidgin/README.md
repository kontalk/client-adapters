Pidgin plugin
=============

This is a plugin for Pidgin. It provides support for:

- [x] Authentication (provided by tunnel script)
- [x] Encryption
- [x] Key retrieval
- [x] Rename users using name from key
- [x] Media support (receive only)
- [ ] Picture thumbnail
- [ ] Registration

## Build

The command below will install the plugin in your home directory under
`~/.purple/plugins`. You'll need Pidgin and GPGME development headers to compile it.

```
make install
```


## Usage

By activating this plugin you will have automatic encryption/decryption for
both incoming and outgoing messages plus automatic public key retrieval and
import into your GnuPG keyring. Buddies with unset name will be renamed with
the name found in the public key.

To enable encryption for outgoing messages, you need to import your personal
key pair (`kontalk-public.asc` and `kontalk-private.asc` from your personal key
archive exported from the app) into GnuPG.  
Take note of the main key ID and paste it into the plugin preferences window.
From that point on, Pidgin will start to encrypt outgoing messages, where
possible, and decrypt incoming messages.


## Authentication support

Kontalk authentication is not supported by Pidgin. We provide two ways to support it.

The first and most compatible way is the Python script hosted in this repository
in the `tunnel` directory. Please refer to its README file for instructions.

The second and more easy way relies on the sole plugin. The plugin itself is able
to create a tunnel internally much like the Python script does, but without starting
any other program. Unfortunately, our dependency GLib is linked against GnuTLS which
has issues with our login certificate. Therefore, you'll need to compile
[another GLib module with OpenSSL support](https://github.com/GNOME/glib-openssl).  
After that, it's just a matter of telling the plugin where to take the certificate
and the private key, host and port to connect to and the port to listen for
connections from Pidgin (pretty much what the Python script asks).

You can disable the internal tunnel of the plugin by setting the listening port
to 0 (default).


## Additional features

You can have support for delivery receipts using another plugin also forked here: [pidgin-xmpp-receipts](//github.com/kontalk/pidgin-xmpp-receipts)
