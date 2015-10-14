# mbed TLS C++ Socket API

The mbed TLS C++ Socket API provides an interface to mbed TLS that looks like the mbed C++ [Socket][] API. In particular, it is event-based, and the classes it defines inherit from the Socket class.

[Socket]: https://github.com/ARMmbed/sockets

It is currently in beta stage, only intended for evaluation.

The following classes (all inheriting from the `Socket` class in the [sockets][Socket] module) are provided:

0. **TLSStream** for TLS clients

The remaining sections of this document provide guidance on using those classes.

## TLSStream

The `TLSStream` class is intended for TLS clients. It inherits from [`TCPStream`](https://github.com/ARMmbed/sockets/blob/master/mbed-net-sockets/TCPStream.h) and is almost a drop-in replacement for it. The only difference is the additional method `setup()` that must be called between constructing the object and calling `connect()`. It expects a pointer to a `mbedtls_ssl_config` structure that you need to allocate and prepare using the various `mbedtls_ssl_conf_xxx()` functions. This structure can be shared between many `TLSStream` objects.

The main things you need to set up in the SSL/TLS configuration are:

0. A cryptographically secure source of (pseudo-)random numbers. In the future a default source might be provided and set up automatically, but for now each application has to to it.
0. A (list of) trusted root(s) for certificate-based authentication. Here, no sensible default can be defined, so it will always be up to the user to decide which certification authorities (CA) to trust, or to configure other means of server authentication. **Warning**: failing to perform server authentication would remove most security guarantees offered by TLS.

An example of using this class can be found in [`test/tls-client`](https://github.com/ARMmbed/mbed-tls-sockets/tree/master/test/tls-client).
