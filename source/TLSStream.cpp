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

#include "mbed-secure-sockets/TLSStream.h"
#include "minar/minar.h"
#include "mbedtls/error.h"

using namespace mbed::Sockets::v0;

/*
 * TODO:
 * - stop using printf for errors/info
 * - extended error code for SSL errors? (Brendan?)
 * - add support for server (will be another backlog item)
 */

TLSStream::TLSStream(const socket_stack_t stack) :
    TCPStream(stack), _onTLSConnect(NULL), _onTLSReadable(NULL), _error(false)
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

    if ((ret = mbedtls_ssl_setup(&_ssl, conf)) != 0) {
        print_mbedtls_error("mbedtls_ssl_setup", ret);
        return SOCKET_ERROR_UNKNOWN;
    }

    if (hostname != NULL) {
        mbedtls_ssl_set_hostname(&_ssl, hostname);
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
                              ConnectHandler_t(this, &TLSStream::onConnect));
}

socket_error_t TLSStream::send(const void * buf, const size_t len) {
    int ret = mbedtls_ssl_write(&_ssl, (const unsigned char *) buf, len);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return SOCKET_ERROR_WOULD_BLOCK;
    }

    if (ret < 0) {
        print_mbedtls_error("mbedtls_ssl_write", ret);
        _error = true;
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
        print_mbedtls_error("mbedtls_ssl_read", ret);
        _error = true;
        return SOCKET_ERROR_UNKNOWN;
    }

    *len = ret;
    return SOCKET_ERROR_NONE;
}

socket_error_t TLSStream::close() {
    mbedtls_ssl_free(&_ssl);
    return TCPStream::close();
}

void TLSStream::print_mbedtls_error(const char *name, int err) {
    char buf[128];
    mbedtls_strerror(err, buf, sizeof (buf));
    printf("%s() failed: -0x%04x (%d): %s\r\n", name, -err, err, buf);
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

void TLSStream::onConnect(TCPStream *s) {
    s->setOnReadable(TCPStream::ReadableHandler_t(this, &TLSStream::onReceive));
    //s->setOnDisconnect(TCPStream::DisconnectHandler_t(this, &TLSStream::onDisconnect));

    /* Start the handshake, the rest will be done in onReceive() */
    int ret = mbedtls_ssl_handshake(&_ssl);
    if (ret < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_mbedtls_error("mbedtls_ssl_handshake", ret);
            _error = true;
        }
        return;
    }
}

void TLSStream::onReceive(Socket *s) {
    (void) s;

    if (_error)
        return;

    if (_ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
        /* Continue the handshake */
        int ret = mbedtls_ssl_handshake(&_ssl);
        if (ret < 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                print_mbedtls_error("mbedtls_ssl_handshake", ret);
                _error = true;
            }
            return;
        }

        /* If we get here, that means we just completed the handshake */
        if (_onTLSConnect) {
            minar::Scheduler::postCallback(_onTLSConnect.bind(this));
        }
    }

    /* Check if data is available to be read */
    unsigned char buf[1];
    int ret = mbedtls_ssl_read(&_ssl, buf, 0);
    if (ret < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            print_mbedtls_error("mbedtls_ssl_read", ret);
            _error = true;
        }
        return;
    }

    /* TODO: distinguish between 0 because len=0 and
     * 0 because EOF */

    /* If we get here, data is available to be read */
    minar::Scheduler::postCallback(_onTLSReadable.bind(this));
}
