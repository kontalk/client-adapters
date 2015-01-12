Generic SSL tunnel bridge
=========================

This script can be used with any standard XMPP client.
It creates a listening socket (defaults on port 5224) which clients can
connect to.

To use this script, you need to export your personal key from the Android
app. You will find a zip file called `kontalk-keys.zip` in your external
storage. You need these two files:

* `kontalk-login.crt`
* `kontalk-login.key`

Please refer to the built-in guide by running:

```
./ssl_bridge.py -h
```
