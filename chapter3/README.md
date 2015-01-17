# Chapter 3: Symmetric Security

This package contains examples for using the ciphersuites covered in
chapter 3. Unless otherwise noted, they generate random nonces (or
initialisation vectors) for each message. They also all use the package
name "secret", so that they can easily be swapped out into a system.

The packages here:

* nacl: XSalsa20 / Poly1305
* aesgcm: AES-256-GCM
* aesctr: AES-256-CTR with HMAC-SHA-384
* aescbc: AES-256-CBC with HMAC-SHA-384 and PKCS #7 padding

This also includes an example of using additional data with an AEAD in
the `aesgcmad` package.
