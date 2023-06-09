# About CryptoEx.Ed project

Extension of the logic in the core library (CryptoEx) to support Ed25519 & Ed448
cryptographic algorithms for digital signatures and X25519 & X448 algorithms
for Diffie-Hellman key agreement. The project also implements JWSs (JSON Web signatures)
and jAdES (Advanced JSON Web Signatures) with EdDSA algorithm.


I have decided to put these on a different project (different from CryptoEx),
mainly because Ed25519, Ed448, X25519 & X448 are still not implemented in
main-stream .NET. So, It need to rely on third-party libraries, such as:

- Bouncy Castle
- *libsodium* based wrappers

At the moment I have decided to use Bounty Castle, because it is 100% managed code
and it is also performance optimized. The CryptoEx.Ed project has a dependency
on Bounty Castle.

The project implements Ed signatures and key-exchanges in an similar to the
standard .NET way and it can be used by .NET developers in a familiar way -
as EC (Elliptic curves) are being used.

As a practical example of the usage of the Ed classes in the library,
I have also extended the classes for JWSs (JSON Web Signatures) and for the
jAdES (Advanced JSON Web Signatures) from the core library to implement EdDSA
algorithm for them.

You can check the code and some documentation pages in the
[Wiki](https://github.com/agyonov/CryptoEx/wiki), for HOWTOs.