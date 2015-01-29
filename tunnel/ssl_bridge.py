#!/usr/bin/env python
# SSL bridge for XMPP STARTTLS
# This code is in the public domain

import argparse

from twisted.internet.protocol import Protocol, Factory
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from twisted.internet import ssl, reactor

PORT = 5222
LISTEN_PORT = 5224

class XMPPClient(Protocol):
    debug = False
    INIT = '<stream:stream to="%s" xmlns="jabber:client" xmlns:stream="http://etherx.jabber.org/streams" version="1.0">'
    SSL_INIT = '<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>'
    SSL_REPLY = ("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", '<proceed xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>')

    def __init__(self, client, domain, cert_file, pkey_file):
        self.client = client
        self.domain = domain
        self.cert_file = cert_file
        self.pkey_file = pkey_file
        self._buf = ''

    def write(self, data):
        """Writes data to the XMPP server."""
        if self.transport and self.transport.TLS:
            if self.debug:
                print 'SEND: %s' % (data, )
            self.transport.write(data)
        else:
            self._buf += data

    def connectionMade(self):
        """Connected to XMPP server."""
        init = self.INIT % self.domain
        if self.debug:
            print 'SEND: %s' % (init, )
        self.transport.write(init)
        reactor.callLater(0.5, self._init2)

    def _init2(self):
        self.transport.write(self.SSL_INIT)

    def dataReceived(self, data):
        if self.debug:
            print 'RECV: %s' % (data, )
        if self.transport.TLS:
            self.client.transport.write(data)
        elif data.endswith(self.SSL_REPLY[0]) or \
	      data.endswith(self.SSL_REPLY[1]):
            if self.debug:
                print 'starting TLS'

            with open(self.pkey_file) as keyFile:
                    with open(self.cert_file) as certFile:
                        clientCert = ssl.PrivateCertificate.loadPEM(
                            keyFile.read() + certFile.read())

            ctx = clientCert.options()
            self.transport.startTLS(ctx)
            if self._buf:
                if self.debug:
                    print 'SEND: %s' % (self._buf, )
                self.transport.write(self._buf)
                self._buf = None


class BridgeProtocol(Protocol):
    debug = False

    def __init__(self, addr, domain, host, port, cert_file, pkey_file):
        self.addr = addr
        self.domain = domain
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.pkey_file = pkey_file
        self._conn = None
        self._buf = ''

    def _connected(self, p):
        self._conn = p

    def dataReceived(self, data):
        # <auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>=</auth>
        if '<auth' in data and 'mechanism' in data and 'PLAIN' in data:
            data = data.replace('PLAIN', 'EXTERNAL')

        self.client.write(data)
        if '</stream:stream>' in data:
            if self.client.transport:
                self.client.transport.loseConnection()
            self.transport.loseConnection()

    def connectionMade(self):
        if self.debug:
            print 'got connection from %s' % (self.addr, )
            print 'connecting to %s:%d' % (self.host, self.port)
        point = TCP4ClientEndpoint(reactor, self.host, self.port)
        self.client = XMPPClient(self, self.domain, self.cert_file, self.pkey_file)
        d = connectProtocol(point, self.client)
        d.addCallback(self._connected)

    def connectionLost(self, reason):
        pass


class BridgeFactory(Factory):
    debug = False

    def __init__(self, domain, host, port, cert_file, pkey_file):
        self.domain = domain
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.pkey_file = pkey_file

    def buildProtocol(self, addr):
        return BridgeProtocol(addr, self.domain, self.host, self.port,
            self.cert_file, self.pkey_file)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='An XMPP bridge for clients not supporting SSL client certificate authentication.')
    parser.add_argument('-d', '--debug', help='enable debug output', action='store_true')
    parser.add_argument('-p', '--port', help='listen for local connections on this port (default: %d)' % LISTEN_PORT, default=LISTEN_PORT)
    parser.add_argument('--domain', help='use this domain for stream initialization', required=True)
    parser.add_argument('-c', '--certificate', help='X.509 certificate file', required=True)
    parser.add_argument('-k', '--privatekey', help='X.509 private key file', required=True)
    parser.add_argument('address', help='forward connections to this host (host:port)')

    args = parser.parse_args()

    if ':' in args.address:
        host, port = args.address.split(':')
        port = int(port)
    else:
        host, port = args.address, PORT

    BridgeFactory.debug = BridgeProtocol.debug = XMPPClient.debug = args.debug

    print 'listening on port %d, forwarding to %s:%d' % (int(args.port), host, port)
    reactor.listenTCP(int(args.port), BridgeFactory(args.domain, host, port, args.certificate, args.privatekey))
    reactor.run()
