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

#include "mbed-tls-sockets/TLSStream.h"
#include "minar/minar.h"
#include "mbedtls/error.h"

using namespace mbed::Sockets::v0;
using namespace mbed::TLS::Sockets;

TLSStream::TLSStream(const socket_stack_t stack) :
    TCPStream(stack), _onTLSConnect(NULL), _onTLSReadable(NULL), _ssl_error(0)
{
    mbedtls_ssl_init(&_ssl);
}

TLSStream::~TLSStream() {
    mbedtls_ssl_free(&_ssl);
}

socket_error_t TLSStream::setup(const mbedtls_ssl_config *conf,
                                const char *hostname)
{
    int ret;

    ret = mbedtls_ssl_setup(&_ssl, conf);
    if (ret != 0) {
        _ssl_error = ret;
        minar::Scheduler::postCallback(_onError.bind(this, SOCKET_ERROR_UNKNOWN));
        return SOCKET_ERROR_UNKNOWN;
    }

    if (hostname != NULL) {
        ret = mbedtls_ssl_set_hostname(&_ssl, hostname);
        if (ret != 0) {
            _ssl_error = ret;
            minar::Scheduler::postCallback(_onError.bind(this, SOCKET_ERROR_UNKNOWN));
        }
    }

    mbedtls_ssl_set_bio(&_ssl, this, ssl_send, ssl_recv, NULL );

    return SOCKET_ERROR_NONE;
}

void TLSStream::setOnReadable(const ReadableHandler_t &onReadable) {
    _onTLSReadable = onReadable;
}

socket_error_t TLSStream::connect(const SocketAddr &address,
                                  const uint16_t port,
                                  const ConnectHandler_t &onConnect) {
    _onTLSConnect = onConnect;

    return TCPStream::connect(address, port,
                              ConnectHandler_t(this, &TLSStream::onTCPConnect));
}

socket_error_t TLSStream::send(const void * buf, const size_t len) {
    int ret = mbedtls_ssl_write(&_ssl, (const unsigned char *) buf, len);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return SOCKET_ERROR_WOULD_BLOCK;
    }

    if (ret < 0) {
        _ssl_error = ret;
        minar::Scheduler::postCallback(_onError.bind(this, SOCKET_ERROR_UNKNOWN));
        return SOCKET_ERROR_UNKNOWN;
    }

    /* TODO: handle partial writes */

    return SOCKET_ERROR_NONE;
}

socket_error_t TLSStream::recv(void * buf, size_t *len) {
    int ret = mbedtls_ssl_read(&_ssl, (unsigned char *) buf, *len);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return SOCKET_ERROR_WOULD_BLOCK;
    }

    if (ret < 0) {
        _ssl_error = ret;
        minar::Scheduler::postCallback(_onError.bind(this, SOCKET_ERROR_UNKNOWN));
        return SOCKET_ERROR_UNKNOWN;
    }

    *len = ret;
    return SOCKET_ERROR_NONE;
}

socket_error_t TLSStream::close() {
    mbedtls_ssl_free(&_ssl);
    return TCPStream::close();
}

int TLSStream::ssl_recv(void *ctx, unsigned char *buf, size_t len) {
    TLSStream *stream = static_cast<TLSStream *>(ctx);
    socket_error_t err = stream->TCPStream::recv(buf, &len);

    if (err == SOCKET_ERROR_NONE) {
        return static_cast<int>(len);
    } else if (err == SOCKET_ERROR_WOULD_BLOCK) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    } else {
        return -1;
    }
}

int TLSStream::ssl_send(void *ctx, const unsigned char *buf, size_t len) {
    TLSStream *stream = static_cast<TLSStream *>(ctx);
    socket_error_t err = stream->TCPStream::send(buf, len);

    if (err == SOCKET_ERROR_NONE) {
        return static_cast<int>(len);
    } else if (err == SOCKET_ERROR_WOULD_BLOCK) {
        return MBEDTLS_ERR_SSL_WANT_WRITE;
    } else {
        return -1;
    }
}

void TLSStream::onTCPConnect(TCPStream *s) {
    (void) s;

    TCPStream::setOnReadable(ReadableHandler_t(this, &TLSStream::onTCPReadable));

    /* Start the handshake, the rest will be done in onTCPReadable() */
    int ret = mbedtls_ssl_handshake(&_ssl);

    if (ret != 0 &&
        ret != MBEDTLS_ERR_SSL_WANT_READ &&
        ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        _ssl_error = ret;
        minar::Scheduler::postCallback(_onError.bind(this, SOCKET_ERROR_UNKNOWN));
    }
}

void TLSStream::onTCPReadable(Socket *s) {
    (void) s;

    if (_ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
        /* Continue the handshake */
        int ret = mbedtls_ssl_handshake(&_ssl);
        if (ret < 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                _ssl_error = ret;
                minar::Scheduler::postCallback(_onError.bind(this, SOCKET_ERROR_UNKNOWN));
            }
            return;
        }

        /* If we get here, that means we just completed the handshake */
        if (_onTLSConnect) {
            minar::Scheduler::postCallback(_onTLSConnect.bind(this));

            return;
        }
    }

    /* Check if data is available to be read */
    unsigned char buf[1];
    int ret = mbedtls_ssl_read(&_ssl, buf, 0);
    if (ret < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            _ssl_error = ret;
            minar::Scheduler::postCallback(_onError.bind(this, SOCKET_ERROR_UNKNOWN));
        }
        return;
    }

    /* TODO: distinguish between 0 because len=0 and
     * 0 because EOF using get_bytes_avail() */

    if (_onTLSReadable) {
        minar::Scheduler::postCallback(_onTLSReadable.bind(this));
    }
}
