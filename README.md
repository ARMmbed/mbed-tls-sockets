# mbed TLS C++ Socket API

The mbed TLS C++ Socket API provides an interface to mbed TLS that looks like the mbed C++ [Socket][] API. In particular, it is event-based, and the classes it defines inherit from the Socket class.

[Socket]: https://github.com/ARMmbed/sockets

It is currently in alpha stage, mainly intended for (internal) evaluation.

Currently only supports TLS clients, not DTLS clients, nor servers of any kind.
