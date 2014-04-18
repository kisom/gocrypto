## reflector

reflector is a stripped-down version of the chat program with all crypto
code removed. It listens for encrypted messages being sent over the
network, and tweaks the first byte in the message (after the nonce)
by adding one to it. It should be run while the chat program is being run.
