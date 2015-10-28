/*
 * Copyright (c) 2015, ARM Limited, All Rights Reserved
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

/** \file main.cpp
 *  \brief An example TLS Client application
 *  This application sends an HTTPS request to developer.mbed.org and searches for a string in
 *  the result.
 *
 *  This example is implemented as a logic class (HelloHTTPS) wrapping a TCP socket.
 *  The logic class handles all events, leaving the main loop to just check if the process
 *  has finished.
 */

/* Change to a number between 1 and 4 to debug the TLS connection */
#define DEBUG_LEVEL 0

/* Change to 1 to skip certificate verification (UNSAFE, for debug only!) */
#define UNSAFE 0

#include "mbed-drivers/mbed.h"
#include "EthernetInterface.h"
#include "mbed-tls-sockets/TLSStream.h"
#include "mbed-drivers/test_env.h"
#include "minar/minar.h"

#include "lwipv4_init.h"

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#if DEBUG_LEVEL > 0
#include "mbedtls/debug.h"
#endif

namespace {
const char *HTTPS_SERVER_NAME = "developer.mbed.org";
const int HTTPS_SERVER_PORT = 443;
const int RECV_BUFFER_SIZE = 600;

const char HTTPS_PATH[] = "/media/uploads/mbed_official/hello.txt";
const size_t HTTPS_PATH_LEN = sizeof(HTTPS_PATH) - 1;

/* Test related data */
const char *HTTPS_OK_STR = "200 OK";
const char *HTTPS_HELLO_STR = "Hello world!";

/* personalization string for the drbg */
const char *DRBG_PERS = "mbed TLS helloword client";

/* List of trusted root CA certificates
 * Currently this is just GlobalSign as it's the root used by developer.mbed.org
 * If you want to trust more that one root, just concatenate them.
 */
const char SSL_CA_PEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG\n"
"A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv\n"
"b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw\n"
"MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i\n"
"YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT\n"
"aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ\n"
"jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp\n"
"xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp\n"
"1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG\n"
"snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ\n"
"U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8\n"
"9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E\n"
"BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B\n"
"AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz\n"
"yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE\n"
"38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP\n"
"AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad\n"
"DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME\n"
"HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==\n"
"-----END CERTIFICATE-----\n";
}

using namespace mbed::Sockets::v0;
using namespace mbed::TLS::Sockets;

/**
 * \brief HelloHTTPS implements the logic for fetching a file from a webserver
 * using a TCP socket and parsing the result.
 */
class HelloHTTPS {
public:
    /**
     * HelloHTTPS Constructor
     * Initializes the TCP socket, sets up event handlers and flags.
     *
     * Note that CThunk is used for event handlers.  This will be changed to a C++
     * function pointer in an upcoming release.
     *
     *
     * @param[in] domain The domain name to fetch from
     * @param[in] port The port of the HTTPS server
     */
    HelloHTTPS(const char * domain, const uint16_t port) :
            _stream(SOCKET_STACK_LWIP_IPV4), _domain(domain), _port(port)
    {

        _error = false;
        _gothello = false;
        _got200 = false;
        _bpos = 0;
        _stream.open(SOCKET_AF_INET4);
        _stream.setOnError(Socket::ErrorHandler_t(this, &HelloHTTPS::onError));

        mbedtls_entropy_init(&_entropy);
        mbedtls_ctr_drbg_init(&_ctr_drbg);
        mbedtls_x509_crt_init(&_cacert);
        mbedtls_ssl_config_init(&_ssl_conf);
    }
    /**
     * Initiate the test.
     *
     * Starts by clearing test flags, then resolves the address with DNS.
     *
     * @param[in] path The path of the file to fetch from the HTTPS server
     */
    void startTest(const char *path) {
        /* Initialize the flags */
        _got200 = false;
        _gothello = false;
        _error = false;
        _disconnected = false;
        /* Fill the request buffer */
        _bpos = snprintf(_buffer, sizeof(_buffer) - 1, "GET %s HTTP/1.1\nHost: %s\n\n", path, HTTPS_SERVER_NAME);

        /*
         * Initialize TLS-related stuf.
         */
        if (mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                    (const unsigned char *) DRBG_PERS,
                    sizeof (DRBG_PERS)) != 0 ||
                mbedtls_x509_crt_parse(&_cacert, (const unsigned char *) SSL_CA_PEM,
                    sizeof (SSL_CA_PEM)) != 0 ||
                mbedtls_ssl_config_defaults(&_ssl_conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
            _error = true;
            return;
        }

        mbedtls_ssl_conf_ca_chain(&_ssl_conf, &_cacert, NULL);
        mbedtls_ssl_conf_rng(&_ssl_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);

#if UNSAFE
        mbedtls_ssl_conf_authmode(&_ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
#endif

#if DEBUG_LEVEL > 0
        mbedtls_ssl_conf_verify(&_ssl_conf, my_verify, NULL);
        mbedtls_ssl_conf_dbg(&_ssl_conf, my_debug, NULL);
        mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

        _stream.setup(&_ssl_conf, _domain);

        /* Connect to the server */
        printf("Starting DNS lookup for %s\r\n", _domain);
        /* Resolve the domain name: */
        socket_error_t err = _stream.resolve(_domain, Socket::DNSHandler_t(this, &HelloHTTPS::onDNS));
        _stream.error_check(err);
    }
    /**
     * Check if the test has completed.
     * @return Returns true if done, false otherwise.
     */
    bool done() {
        return _error || (_got200 && _gothello);
    }
    /**
     * Check if there was an error
     * @return Returns true if there was an error, false otherwise.
     */
    bool error() {
        return _error;
    }
protected:
#if DEBUG_LEVEL > 0
    /**
     * Debug callback for mbed TLS
     * Just prints on the USB serial port
     */
    static void my_debug(void *ctx, int level, const char *file, int line,
                         const char *str)
    {
        const char *p, *basename;
        (void) ctx;

        /* Extract basename from file */
        for(p = basename = file; *p != '\0'; p++) {
            if(*p == '/' || *p == '\\') {
                basename = p + 1;
            }
        }

        printf("%s:%04d: |%d| %s", basename, line, level, str);
    }

    /**
     * Certificate verification callback for mbed TLS
     * Here we only use it to display information on each cert in the chain
     */
    static int my_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
    {
        char buf[1024];
        (void) data;

        printf("\nVerifying certificate at depth %d:\n", depth);
        mbedtls_x509_crt_info(buf, sizeof (buf) - 1, "  ", crt);
        printf("%s", buf);

        if (*flags == 0)
            printf("No verification issue for this certificate\n");
        else
        {
            mbedtls_x509_crt_verify_info(buf, sizeof (buf), "  ! ", *flags);
            printf("%s\n", buf);
        }

        return 0;
    }
#endif
    void onError(Socket *s, socket_error_t err) {
        (void) s;
        printf("MBED: Socket Error: %s (%d)\r\n", socket_strerror(err), err);
        if (_stream.getTLSError()) {
            char buf[128];
            int ret = _stream.getTLSError(buf, sizeof buf);
            printf("MBED: TLS Error: %04x: %s\r\n", -ret, buf);
        }

        _stream.close();
        _error = true;
        printf("{{%s}}\r\n",(error()?"failure":"success"));
        printf("{{end}}\r\n");
    }
    /**
     * On Connect handler
     * Sends the request which was generated in startTest
     */
    void onConnect(TCPStream *s) {
        char buf[16];
        _remoteAddr.fmtIPv4(buf,sizeof(buf));
        printf("Connected to %s:%d\r\n", buf, _port);
        /* Send the request */
        s->setOnReadable(Socket::ReadableHandler_t(this, &HelloHTTPS::onReceive));
        s->setOnDisconnect(TCPStream::DisconnectHandler_t(this, &HelloHTTPS::onDisconnect));
        printf("Sending HTTPS Get Request...\r\n");
        socket_error_t err = _stream.send(_buffer, _bpos);
        s->error_check(err);
    }
    /**
     * On Receive handler
     * Parses the response from the server, to check for the HTTPS 200 status code and the expected response ("Hello World!")
     */
    void onReceive(Socket *s) {
        printf("HTTPS Response received.\r\n");
        _bpos = sizeof(_buffer);
        /* Read data out of the socket */
        socket_error_t err = s->recv(_buffer, &_bpos);
        if (err != SOCKET_ERROR_NONE) {
            onError(s, err);
            return;
        }
        _buffer[_bpos] = 0;
        /* Check each of the flags */
        _got200 = _got200 || strstr(_buffer, HTTPS_OK_STR) != NULL;
        _gothello = _gothello || strstr(_buffer, HTTPS_HELLO_STR) != NULL;
        /* Print status messages */
        printf("HTTPS: Received %d chars from server\r\n", _bpos);
        printf("HTTPS: Received 200 OK status ... %s\r\n", _got200 ? "[OK]" : "[FAIL]");
        printf("HTTPS: Received '%s' status ... %s\r\n", HTTPS_HELLO_STR, _gothello ? "[OK]" : "[FAIL]");
        printf("HTTPS: Received message:\r\n\r\n");
        printf("%s", _buffer);
        _error = !(_got200 && _gothello);

        s->close();
    }
    /**
     * On DNS Handler
     * Reads the address returned by DNS, then starts the connect process.
     */
    void onDNS(Socket *s, struct socket_addr addr, const char *domain) {
        /* Check that the result is a valid DNS response */
        if (socket_addr_is_any(&addr)) {
            /* Could not find DNS entry */
            printf("Could not find DNS entry for %s", HTTPS_SERVER_NAME);
            onError(s, SOCKET_ERROR_DNS_FAILED);
        } else {
            /* Start connecting to the remote host */
            char buf[16];
            _remoteAddr.setAddr(&addr);
            _remoteAddr.fmtIPv4(buf,sizeof(buf));
            printf("DNS Response Received:\r\n%s: %s\r\n", domain, buf);
            printf("Connecting to %s:%d\r\n", buf, _port);
            socket_error_t err = _stream.connect(_remoteAddr, _port, TCPStream::ConnectHandler_t(this, &HelloHTTPS::onConnect));

            if (err != SOCKET_ERROR_NONE) {
                onError(s, err);

            }
        }
    }
    void onDisconnect(TCPStream *s) {
        s->close();
        printf("{{%s}}\r\n",(error()?"failure":"success"));
        printf("{{end}}\r\n");
    }

protected:
    TLSStream _stream;              /**< The TLS Socket */
    const char *_domain;            /**< The domain name of the HTTPS server */
    const uint16_t _port;           /**< The HTTPS server port */
    char _buffer[RECV_BUFFER_SIZE]; /**< The response buffer */
    size_t _bpos;                   /**< The current offset in the response buffer */
    SocketAddr _remoteAddr;         /**< The remote address */
    volatile bool _got200;          /**< Status flag for HTTPS 200 */
    volatile bool _gothello;        /**< Status flag for finding the test string */
    volatile bool _error;           /**< Status flag for an error */
    volatile bool _disconnected;

    mbedtls_entropy_context _entropy;
    mbedtls_ctr_drbg_context _ctr_drbg;
    mbedtls_x509_crt _cacert;
    mbedtls_ssl_config _ssl_conf;
};

/**
 * The main loop of the HTTPS Hello World test
 */
EthernetInterface eth;
HelloHTTPS *hello;

void app_start(int, char*[]) {
    /* The default 9600 bps is too slow to print full TLS debug info and could
     * cause the other party to time out. Select a higher baud rate for
     * printf(), regardless of debug level for the sake of uniformity. */
    Serial pc(USBTX, USBRX);
    pc.baud(115200);

    printf("{{start}}\r\n");

    /* Initialise with DHCP, connect, and start up the stack */
    eth.init();
    eth.connect();
    lwipv4_socket_init();

    hello = new HelloHTTPS(HTTPS_SERVER_NAME, HTTPS_SERVER_PORT);

    printf("Client IP Address is %s\r\n", eth.getIPAddress());

    mbed::util::FunctionPointer1<void, const char*> fp(hello, &HelloHTTPS::startTest);
    minar::Scheduler::postCallback(fp.bind(HTTPS_PATH));
}
