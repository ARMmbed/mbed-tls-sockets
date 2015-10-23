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

#ifndef __MBED_TLS_SOCKETS_TLSSTREAM_H__
#define __MBED_TLS_SOCKETS_TLSSTREAM_H__

#include "sockets/TCPStream.h"
#include "mbedtls/ssl.h"

namespace mbed {
namespace TLS {
namespace Sockets {

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
     *
     * @return  A socket error code. SOCKET_ERROR_WOULD_BLOCK means you need
     * to call this again in order to send the TLS close notify message.
     */
    socket_error_t close();

    /**
     * Checks the socket status to determine whether it is connected.
     * @return true if the socket is connected, false if it is not
     */
    bool isConnected() const;

    /**
     * Get the last SSL/TLS error code and description.
     * When a method returns \c SOCKET_ERROR_UNKNOWN, call this to get more
     * details about the error.
     *
     * @param buf   Buffer to write the error description to.
     *              If missing or NULL, no error description will be written.
     * @param len   Size of the buffer in bytes.
     * @return      The underlying mbed TLS error code.
     */
    int getTLSError(char *buf = NULL, size_t len = 0) const;

protected:
    /**
     * Receive callback for mbed TLS
     */
    static int ssl_recv(void *ctx, unsigned char *buf, size_t len);

    /**
     * Send callback for mbed TLS
     */
    static int ssl_send(void *ctx, const unsigned char *buf, size_t len);

    /**
     * On TCP Connect handler
     * Start the TLS handshake
     */
    void onTCPConnect(TCPStream *s);

    /**
     * On TCP Readable handler
     * Complete the handshake if not done yet,
     * or forward ApplicationData from the TLS layer to the user
     */
    void onTCPReadable(Socket *s);

    ConnectHandler_t _onTLSConnect;     /**< User connect handler   */
    ReadableHandler_t _onTLSReadable;   /**< User read handler      */

    mbedtls_ssl_context _ssl;           /**< TLS context            */
    int _ssl_error;                     /**< Last TLS error         */
};

} // namespace Sockets
} // namespace TLS
} // namespace mbed

#endif /* __MBED_TLS_SOCKETS_TLSSTREAM_H__ */
