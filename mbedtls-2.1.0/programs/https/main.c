/*
 *  Classic "Hello, world" demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#if 0
#define MBEDTLS_THREADING_IMPL
#define MBEDTLS_CONFIG_FILE "config-mtk-basic.h"



#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include "config-mtk-basic.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

//for tls
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

int main( void )
{
	mbedtls_printf("begin https download test\r\n");

	//init tls
	mbedtls_net_context* server_fd = &tls_conn->server_fd;
    mbedtls_entropy_context* entropy = &tls_conn->entropy;
    mbedtls_ctr_drbg_context* ctr_drbg = &tls_conn->ctr_drbg;
    mbedtls_ssl_context* ssl = &tls_conn->ssl;
    mbedtls_ssl_config* conf = &tls_conn->conf;
    mbedtls_ssl_session* saved_session = &tls_conn->saved_session;
    mbedtls_x509_crt* cacert = &tls_conn->cacert;




#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( 0 );
}

#else

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <unistd.h> /* read, write, close */

#define SERVER_PORT 80
//#define SERVER_NAME "cnbj0.fds.api.xiaomi.com"
#define SERVER_NAME "111.206.200.99"
//#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define GET_REQUEST "GET /miio_fw/17714cb00fb2cda06b8a7081f40abe18_upd_xiaomi.dev.mtk1.bin?GalaxyAccessKeyId=5721718224520&Expires=1509503829000&Signature=bEhBhopqEY4crzyjp+X4jOjLtdw= HTTP/1.1\r\nHost: cnbj0.fds.api.xiaomi.com\r\nAccept: */*\r\n\r\n"

int main( void )
{
    int ret = 0, len, server_fd = 0;
    unsigned char buf[1024];
    struct sockaddr_in server_addr;
    struct hostent *server_host;

    /*
     * Start the connection
     */
    printf( "\n  . Connecting to tcp/%s/%4d...", SERVER_NAME,
                                                 SERVER_PORT );
    fflush( stdout );

    if( ( server_host = gethostbyname( SERVER_NAME ) ) == NULL )
    {
        printf( " failed\n  ! gethostbyname failed\n\n");
        goto exit;
    }

    if( ( server_fd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP) ) < 0 )
    {
        printf( " failed\n  ! socket returned %d\n\n", server_fd );
        goto exit;
    }

    memcpy( (void *) &server_addr.sin_addr,
            (void *) server_host->h_addr,
                     server_host->h_length );

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons( SERVER_PORT );

    if( ( ret = connect( server_fd, (struct sockaddr *) &server_addr,
                         sizeof( server_addr ) ) ) < 0 )
    {
        printf( " failed\n  ! connect returned %d\n\n", ret );
        goto exit;
    }

    printf( " ok\n" );

    /*
     * Write the GET request
     */
    printf( "  > Write to server:" );
    fflush( stdout );

    len = sprintf( (char *) buf, GET_REQUEST );

    while( ( ret = write( server_fd, buf, len ) ) <= 0 )
    {
        if( ret != 0 )
        {
            printf( " failed\n  ! write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    printf( " %d bytes written\n\n%s", len, (char *) buf );

    /*
     * Read the HTTP response
     */
    printf( "  < Read from server:" );
    fflush( stdout );
    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = read( server_fd, buf, len );

        if( ret <= 0 )
        {
            printf( "failed\n  ! ssl_read returned %d\n\n", ret );
            break;
        }

        len = ret;
//        printf( " %d bytes read\n\n%s", len, (char *) buf );
        printf( " %d bytes read\n\n", len );
    }
    while( 1 );

exit:

    close( server_fd );

#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif
