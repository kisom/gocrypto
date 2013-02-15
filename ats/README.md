[ ats ]

authenticating time server: a simple example of an authenticating time
server. the server computes a nonce, sends it to the client, who must
encrypt it and send it back to the server. if it decrypts successfully,
the server will send the client the secret.
