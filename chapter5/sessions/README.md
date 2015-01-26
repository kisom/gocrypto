## sessions

This is an example of signed sessions. It is based on the `Identity` type
that contains an Ed25519 signature key. It establishes a bidirectional
secure channel over an insecure channel. An Identity has a list of known
peers, and supports a function for looking up a peer to determine if it
is trusted.

There are two parties in a session: the dialer intitiates the session
with a listener. At the start of the session, the dialer sends its two
public keys to the listener, who responds with its own public keys. The
first public key is used to encrypt traffic going from the dialer to the
listener, and the second is used to encrypt traffic from the listener
to the dialer.


## Security model

It is assumed that there is a mechanism in place for exchanging
public keys. The `PeerLookup` method is designed to support a
variety of PKI scenarios, including keyservers or directory lookups.

Only the initial key exchange is signed: it assumed after this point
that the peers have authenticated, and that the established secure
channel is suitable for negotiating new session keys as needed.

The primary attack surface is the initial key exchange. An attacker
who can subvert the peer lookup process or have an Identity trust their
keys, or perform a DoS attack on the peer lookup process, can subvert
the authentication mechanism or prevent peers from communicating,
respectively.


