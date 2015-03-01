Pidgin plugin
=============

This is a plugin for Pidgin. It provides support for:

* Authentication (provided by tunnel script) :white_check_mark:
* Encryption :white_check_mark:
* Key retrieval :white_check_mark:
* Media support (receive only) :white_check_mark:
* Picture thumbnail
* Registration

## Build

The command below will install the plugin in your home directory under
`~/.purple/plugins`. You'll need Pidgin and GPGME development headers to compile it.

```
make install
```


## Usage

By activating this plugin you will have automatic encryption/decryption for
both incoming and outgoing messages plus automatic public key retrieval and
import into your GnuPG keyring.

To enable encryption for outgoing messages, you need to import your personal
key pair (`kontalk-public.asc` and `kontalk-private.asc` from your personal key
archive exported from the app) into GnuPG.  
Take note of the main key ID and paste it into the plugin preferences window.
From that point on, Pidgin will start to encrypt outgoing messages, where
possible, and decrypt incoming messages.


## Additional features

You can have support for delivery receipts using another plugin also forked here: [pidgin-xmpp-receipts](/kontalk/pidgin-xmpp-receipts)
