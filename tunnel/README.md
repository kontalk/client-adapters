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


## Installation

You can install the script in any directory you like.
You will need:

 * Python >= 2.7
 * [Twisted](http://twistedmatrix.com/) >= 13.x


## Usage

This scripts will listen on a port that your preferred XMPP client will connect
to. Here is an example command line:

```
./ssl_bridge.py -d \
--domain beta.kontalk.net \
-c kontalk-login.crt \
-k kontalk-login.key \
beta.kontalk.net:5999
```

The script will listen on the default port 5224 for connections and create a
bridge to `beta.kontalk.net` on port 5999, doing the SSL handshake for you.  
Setup your XMPP client to make an **unencrypted connection and to use plain
authentication** (credentials don't matter, they will be discarded by the script,
however you will need to use the domain you passed to `--domain`).  
The `-p` parameter is optional and indicates the port it will listen for
incoming connections.  
The `-d` parameter is also optional and instructs the script to print debugging
information along with a complete dump of the XMPP traffic between client and
server.

For more information, please refer to the built-in guide by running:

```
./ssl_bridge.py -h
```
