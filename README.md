# EDHOC-C
First of all, initial work is done by [alexkrontiris](https://github.com/alexkrontiris/Enrollment-over-EDHOC)
This is an implementation of IETF draft [Ephemeral Diffie-Hellman Over COSE (EDHOC)](https://tools.ietf.org/html/draft-selander-ace-cose-ecdhe-08) in C.

EDHOC is a compact, ligtweight authentication Diffie-Hellman key exchange protocol with ephemeral keys that can be used over any applicaiton layer. EDHOC messages are encoded with the Consise Binary Object Representation (CBOR) format which is based on the Javascript Object Notation (JSON) data model and the CBOR Object Signing and Encryption (COSE) which specifies how to process encryption, signatures and Message Authentication Code (MAC) operations.


## Supported authentication

EDHOC supports authentication using pre-shared keys (PSK)

### Dependencies

OpenSSL version 1.1.0 (includes X25519 elliptic curve) or newer

libb64 (Base64 Encoding/Decoding Routines)

libcbor (CBOR format implementation for C)



### TODO

Replace openssl with [cose-c](https://github.com/cose-wg/COSE-C) 
Add documentation