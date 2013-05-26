/*
   bench is a cryptographic benchmark package.

   This is a sample benchmark package demonstrating the compuational cost
   of public key cryptography compared to symmetric cryptography. It
   compares the cost of generating keys, and encrypting/decrypting a short
   string.

   Symmetric: AES128-CTR with appended HMAC-SHA256
   Asymmetric: RSA 3072 OAEP using SHA256

   It is a standalone package with only standard library dependencies.
*/
package bench
