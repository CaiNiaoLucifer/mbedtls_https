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

//#define MBEDTLS_THREADING_IMPL
//#define MBEDTLS_CONFIG_FILE "config-mtk-basic.h"
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"


#define LOG_DEBUG printf
#define LOG_INFO printf
#define LOG_WARN printf

#define MBEDTLS_DEBUG_LEVEL 5

#define SERVER_PORT 443
//#define SERVER_NAME "cnbj0.fds.api.xiaomi.com"
//#define SERVER_NAME "111.206.200.99"
#define SERVER_NAME "36.250.240.133"
//#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define GET_REQUEST "GET /miio_fw/17714cb00fb2cda06b8a7081f40abe18_upd_xiaomi.dev.mtk1.bin?GalaxyAccessKeyId=5721718224520&Expires=1516523408000&Signature=pqr1TAdlQFlEMb0E8HAIJXWvu2E= HTTP/1.1\r\nAccept: */*\r\n\r\n"

const char ota_server_root_cert[]=
"-----BEGIN CERTIFICATE-----\r\n"
"MIIEADCCAuigAwIBAgIBADANBgkqhkiG9w0BAQUFADBjMQswCQYDVQQGEwJVUzEh\r\n"
"MB8GA1UEChMYVGhlIEdvIERhZGR5IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBE\r\n"
"YWRkeSBDbGFzcyAyIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTA0MDYyOTE3\r\n"
"MDYyMFoXDTM0MDYyOTE3MDYyMFowYzELMAkGA1UEBhMCVVMxITAfBgNVBAoTGFRo\r\n"
"ZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR28gRGFkZHkgQ2xhc3Mg\r\n"
"MiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTCCASAwDQYJKoZIhvcNAQEBBQADggEN\r\n"
"ADCCAQgCggEBAN6d1+pXGEmhW+vXX0iG6r7d/+TvZxz0ZWizV3GgXne77ZtJ6XCA\r\n"
"PVYYYwhv2vLM0D9/AlQiVBDYsoHUwHU9S3/Hd8M+eKsaA7Ugay9qK7HFiH7Eux6w\r\n"
"wdhFJ2+qN1j3hybX2C32qRe3H3I2TqYXP2WYktsqbl2i/ojgC95/5Y0V4evLOtXi\r\n"
"EqITLdiOr18SPaAIBQi2XKVlOARFmR6jYGB0xUGlcmIbYsUfb18aQr4CUWWoriMY\r\n"
"avx4A6lNf4DD+qta/KFApMoZFv6yyO9ecw3ud72a9nmYvLEHZ6IVDd2gWMZEewo+\r\n"
"YihfukEHU1jPEX44dMX4/7VpkI+EdOqXG68CAQOjgcAwgb0wHQYDVR0OBBYEFNLE\r\n"
"sNKR1EwRcbNhyz2h/t2oatTjMIGNBgNVHSMEgYUwgYKAFNLEsNKR1EwRcbNhyz2h\r\n"
"/t2oatTjoWekZTBjMQswCQYDVQQGEwJVUzEhMB8GA1UEChMYVGhlIEdvIERhZGR5\r\n"
"IEdyb3VwLCBJbmMuMTEwLwYDVQQLEyhHbyBEYWRkeSBDbGFzcyAyIENlcnRpZmlj\r\n"
"YXRpb24gQXV0aG9yaXR5ggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD\r\n"
"ggEBADJL87LKPpH8EsahB4yOd6AzBhRckB4Y9wimPQoZ+YeAEW5p5JYXMP80kWNy\r\n"
"OO7MHAGjHZQopDH2esRU1/blMVgDoszOYtuURXO1v0XJJLXVggKtI3lpjbi2Tc7P\r\n"
"TMozI+gciKqdi0FuFskg5YmezTvacPd+mSYgFFQlq25zheabIZ0KbIIOqPjCDPoQ\r\n"
"HmyW74cNxA9hi63ugyuV+I6ShHI56yDqg+2DzZduCLzrTia2cyvk0/ZM/iZx4mER\r\n"
"cEr/VxqHD3VILs9RaRegAhJhldXRQLIQTO7ErBBDpqWeCtWVYpoNz4iCxTIM5Cuf\r\n"
"ReYNnyicsbkqWletNw+vHX/bvZ8=\r\n"
"-----END CERTIFICATE-----\r\n";

static void my_debug( void *ctx, int level,
                      const char *file, int line, const char *str )
{
    ((void) level);
    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

int main( void )
{
    int ret = 0, len;

    /*
     * mbedtls config
     */
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_ssl_session saved_session;
    mbedtls_x509_crt cacert;

    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    memset(&saved_session, 0, sizeof( mbedtls_ssl_session));

    mbedtls_entropy_init( &entropy );


    /*
     * 0. Initialize the RNG and the session data
     */
    LOG_DEBUG( ".Seeding the random number generator...\n\r" );
    const char *pers = "mbedtls_pc";




    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    LOG_DEBUG( " ok\n" );

    /*
     * 1. Initialize cert if need
     */
    	LOG_INFO( "  . Loading the CA root certificate ...\n\r");
    	const char *cert = ota_server_root_cert;
	ret = mbedtls_x509_crt_parse( &cacert, (const unsigned char *) cert, strlen(cert)+1 );
	if( ret < 0 ){
		LOG_WARN( " failed  !  mbedtls_x509_crt_parse returned -0x%x\n", -ret );
		goto exit;
	}
	LOG_DEBUG( " ok (%d skipped)\n", ret );


    /*
     * 2. Start the connection
     */
	char port_str[16];
	const char * host = SERVER_NAME;
	uint16_t port = SERVER_PORT;
	snprintf(port_str, sizeof(port_str), "%d", port);
	LOG_INFO(" tls: connect to server %s ,port is %s.\n\r",host, port_str);
	if( (ret = mbedtls_net_connect( &server_fd, host, port_str, MBEDTLS_NET_PROTO_TCP) ) != 0){
		LOG_WARN( " failed ! mbedtls_net_connect returned -0x%x\n\n", -ret );
		goto exit;
	}

    /*
     * 3. Setup conf
     */

	#ifdef MBEDTLS_DEBUG_C
	mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LEVEL);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
	#endif

    LOG_DEBUG( "  . Setting up the SSL/TLS structure...a" );
    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
					MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
    	LOG_WARN( " failed ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret );
        goto exit;
    }

	//MBEDTLS_SSL_VERIFY_NONE: peer certificate is not checked (default on server) (insecure on client)
	//MBEDTLS_SSL_VERIFY_OPTIONAL: peer certificate is checked, however the handshake continues even if verification failed; mbedtls_ssl_get_verify_result() can be called after the handshake is complete.
	//MBEDTLS_SSL_VERIFY_REQUIRED: peer must present a valid certificate, handshake is aborted if verification failed. (default on client)
	mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );//optional,not required,only solve Network hijacking
	mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
	mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );

	 /*
	 * 4. ssl setup
	 */
	if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
	{
		LOG_WARN( " failed ! mbedtls_ssl_setup returned -0x%x\n\n", -ret );
		goto exit;
	}

	if( ( ret = mbedtls_ssl_set_hostname( &ssl, host ) ) != 0 )
	{
		LOG_WARN( " failed ! mbedtls_ssl_set_hostname returned -0x%x\n\n", -ret );
		goto exit;
	}

	mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    /*
     * 5. handshake
     */
    LOG_INFO( " now, start handshake...\n\r" );
    if( ( ret = mbedtls_ssl_handshake(&ssl) ) != 0 )
    {
    		LOG_WARN( " failed ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret );
    		goto exit;
    }

    /*
     * 6. read
     */
    //: mbedtls_ssl_read()，return n:n>=0成功读取到的数据,<0:read error

    uint8_t buf[1540];
    uint16_t buf_len;
    while(1){
    		LOG_DEBUG("trying to read\r\n");
		ret = mbedtls_ssl_read( &ssl, buf, sizeof(buf));
		if(ret < 0){
			if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ){
				buf_len = 0;
				goto exit;
			}
			else{
				//对方断开的连接
				if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
					LOG_DEBUG("tls: peer close notify.\n\r");
				else if(ret == MBEDTLS_ERR_NET_CONN_RESET )
					LOG_DEBUG("tls: peer reset.\n\r");
				buf_len = 0;
				goto exit;
			}
		}
		else{//recv data
			buf[ret] = '\0';
			buf_len = ret;
			LOG_DEBUG("received %d\r\n", ret);
			//server connected hook
		}
    }

	return( ret );
exit:
	LOG_WARN("tls:connect to server failed.\n\r");
	mbedtls_net_free( &server_fd );
#if defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt_free( &cacert );
#endif
	mbedtls_ssl_free( &ssl );
	mbedtls_ssl_config_free( &conf );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );
	LOG_DEBUG("error byebye!");

#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif
