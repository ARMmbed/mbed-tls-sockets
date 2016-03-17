# HTTPS File Download Example for TLS Client

This application downloads a file from an HTTPS server (developer.mbed.org) and looks for a specific string in that file.

This example is implemented as a logic class (HelloHTTPS) wrapping a `TLSStream` object. The logic class handles all events, leaving the main loop to just check if the process has finished.

## Pre-requisites

To build and run this example you must have:

* A computer with the following software installed:
  * [CMake](http://www.cmake.org/download/).
  * [yotta](https://github.com/ARMmbed/yotta). Please note that **yotta has its own set of dependencies**, listed in the [installation instructions](http://armmbed.github.io/yotta/#installing-on-windows).
  * [Python](https://www.python.org/downloads/).
  * [The ARM GCC toolchain](https://launchpad.net/gcc-arm-embedded).
  * A serial terminal emulator (Like screen, pySerial and cu).
* An [FRDM-K64F](http://developer.mbed.org/platforms/FRDM-K64F/) development board, or another board supported by mbed OS (in which case you'll have to substitute frdm-k64f-gcc with the appropriate target in the instructions below).
* A micro-USB cable.
* An Ethernet connection to the internet.
* An Ethernet cable.
* If your OS is Windows, please follow the installation instructions [for the serial port driver](https://developer.mbed.org/handbook/Windows-serial-configuration).

## Getting started

1. Connect the FRDM-K64F to the internet using the Ethernet cable.

2. Connect the FRDM-K64F to the computer with the micro-USB cable, being careful to use the "OpenSDA" connector on the target board.

3. Navigate to the mbed-tls-sockets directory supplied with your release and open a terminal.

4. Set the yotta target:

    ```
    yotta target frdm-k64f-gcc
    ```

5. Build mbed-tls-sockets and the examples. This will take a long time if it is the first time:

    ```
    $ yotta build
    ```

6. Copy `build/frdm-k64f-gcc/test/mbed-tls-sockets-test-tls-client.bin` to your mbed board and wait until the LED next to the USB port stops blinking.

7. Start the serial terminal emulator and connect to the virtual serial port presented by FRDM-K64F.

	Use the following settings:

	* 115200 baud (not 9600).
	* 8N1.
	* No flow control.

8. Press the Reset button on the board.

9. The output in the terminal window should look similar to this:

    ```
    {{start}}
    Client IP Address is 192.168.0.2
    Starting DNS lookup for developer.mbed.org
    DNS Response Received:
    developer.mbed.org: 217.140.101.20
    Connecting to 217.140.101.20:443
    Connected to 217.140.101.20:443
    Sending HTTPS Get Request...
    HTTPS Response received.
    HTTPS: Received 440 chars from server
    HTTPS: Received 200 OK status ... [OK]
    HTTPS: Received 'Hello world!' status ... [OK]
    HTTPS: Received message:

    HTTP/1.1 200 OK
    Server: nginx/1.7.10
    Date: Wed, 14 Oct 2015 15:42:03 GMT
    Content-Type: text/plain
    Content-Length: 14
    Connection: keep-alive
    Last-Modified: Fri, 27 Jul 2012 13:30:34 GMT
    Accept-Ranges: bytes
    Cache-Control: max-age=36000
    Expires: Thu, 15 Oct 2015 01:42:03 GMT
    X-Upstream-L3: 172.17.42.1:8080
    X-Upstream-L2: developer-sjc-cyan-2-nginx
    Strict-Transport-Security: max-age=31536000; includeSubdomains

    Hello world!
    {{success}}
    {{end}}
    ```

## Debugging the TLS connection

If you are experiencing problems with this example, you should first rule out network issues by making sure the [simple HTTP file downloader example](https://github.com/ARMmbed/mbed-example-network-private/tree/master/test/helloworld-tcpclient) for the TCP module works as expected. If not, please follow the debug instructions for the HTTP file example before proceeding with the instructions below.

To print out more debug information about the TLS connection, edit the file `test/tls-client/main.cpp` and change the definition of `DEBUG_LEVEL` (near the top of the file) from 0 to a positive number:

* Level 1 only prints non-zero return codes from SSL functions and information about the full certificate chain being verified.

* Level 2 prints more information about internal state updates.

* Level 3 is intermediate.

* Level 4 (the maximum) includes full binary dumps of the packets.


If the TLS connection is failing with an error similar to:

    ```
    MBED: TLS Error: -0x2700: X509 - Certificate verification failed, e.g. CRL, CA or signature check failed
    ```

it probably means you need to update the contents of the `SSL_CA_PEM` constant (this can happen if you modify `HTTPS_SERVER_NAME`, or when `developer.mbed.org` switches to a new CA when updating its certificate). 

Another reason for this error may be a proxy providing a different certificate. Proxies can be used in some network configurations or for performing man-in-the-middle attacks. If you choose to ignore this error and proceed with the connection anyway, you can change the definition of `UNSAFE` near the top of the file from 0 to 1. **Warning:** this removes all security against a possible active attacker, use for tests only, never in production!
