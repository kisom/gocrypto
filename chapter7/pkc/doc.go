/*
   pkc is an example of using RSA public-key cryptography. It provides
   examples for generating keys, importing and exporting keys in both
   DER and PEM format, and encrypting/decrypting data. The package uses
   RSAES-OAEP with SHA256, and provides the same level of cryptographic
   security as AES-128.

   There is also an example of a keychain, implemented as a single RSA
   private key with multiple public keys. The public keys are assigned
   a optional string identifier.
*/
package pkc
