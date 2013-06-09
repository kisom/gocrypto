/*
   pkc is an example of using RSA public-key cryptography for digital
   signatures. It provides examples for generating keys, importing and
   exporting keys in both DER and PEM format, and signing/verifying
   messages. The package uses RSASSA-PSS with SHA256, and provides the
   same level of cryptographic security as AES-128.

   There is also an example of a keychain, implemented as a single RSA
   private key with multiple public keys. The public keys are assigned
   a optional string identifier.
*/
package pks
