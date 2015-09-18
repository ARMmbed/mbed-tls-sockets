/*
 * Copyright (c) 2015-2015, ARM Limited, All Rights Reserved
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __MBED_SECURE_SOCKETS_TLSSTREAM_H__
#define __MBED_SECURE_SOCKETS_TLSSTREAM_H__

#include "mbed-net-sockets/TCPStream.h"
#include "mbedtls/ssl.h"

/*
 * TODO:
 * - namespacing
 */

class TLSStream : public mbed::Sockets::v0::TCPStream {
public:
    /**
     * TLSStream constructor
     */
    TLSStream(const socket_stack_t stack);

    /**
     * TLSStream destructor
     */
    ~TLSStream();

    /**
     * Set up the TLS connection.
     *
     * @note This method must be called before connect() can be used.
     *
     * @param conf      SSL/TLS configuration
     * @param hostname  Expected hostname for certificate verification
     *
     * @note hostname may be ommited if peer verification is also disabled in
     * the configuration (Warning: this is insecure on clients).
     */
    socket_error_t setup(const mbedtls_ssl_config *conf,
                         const char *hostname = NULL);

    /**
     * Connect (and execute a TLS handshake) with peer
     */
    socket_error_t connect(const mbed::Sockets::v0::SocketAddr &address,
                           const uint16_t port,
                           const ConnectHandler_t &onConnect);

    /**
     * Set the onReadable callback
     */
    void setOnReadable(const ReadableHandler_t &onReadable);

    /**
     * Send data over an open connection
     */
    socket_error_t send(const void * buf, const size_t len);

    /**
     * Receive data over an open connection
     */
    socket_error_t recv(void * buf, size_t *len);

    /**
     * Close the connection
     */
    socket_error_t close();

protected:
    /**
     * Helper for pretty-printing mbed TLS error codes
     */
    static void print_mbedtls_error(const char *name, int err);

    /**
     * Receive callback for mbed TLS
     */
    static int ssl_recv(void *ctx, unsigned char *buf, size_t len);

    /**
     * Send callback for mbed TLS
     */
    static int ssl_send(void *ctx, const unsigned char *buf, size_t len);

    /**
     * On Connect handler
     * Start the TLS handshake
     */
    void onConnect(TCPStream *s);

    /**
     * On Receive handler
     * Complete the handshake if not done yet,
     * or forward ApplicationData from the TLS layer to the user
     */
    void onReceive(Socket *s);

    ConnectHandler_t _onTLSConnect;     /**< User connect handler   */
    ReadableHandler_t _onTLSReadable;   /**< User read handler      */

    mbedtls_ssl_context _ssl;       /**< TLS context */

    volatile bool _error;           /**< Status flag for errors */
};

#endif /* __MBED_SECURE_SOCKETS_TLSSTREAM_H__ */
