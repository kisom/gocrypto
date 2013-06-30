/*
   The hash package provides a wrapper around the Go hash
   packages.  Specifically, it extends the package to provide
   verification of digests. The default hash algorithm used is
   SHA-256, but provisions are made to support other algorithms.

   Two functions are provided for computing hashes: New computes the digest
   of a byte slice, and Read computes the digest of an io.Reader. The
   returned Digest type has four methods of note.

   The Digest and HexDigest methods return the binary and hexadecimal
   hashes, respectively.

   The Verify and VerifyRead compare the Digest to the byte slice
   or io.Reader, respectively, returning a boolean value indicating
   whether the digests match.
*/
package hash
