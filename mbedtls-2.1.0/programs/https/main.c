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
#include <stdlib.h> /* malloc, free*/

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
#define LOG_ERROR printf

#define MBEDTLS_DEBUG_LEVEL 0
//https://cdn.cnbj0e.fds.api.mi-img.com/miio_fw/b53ff7643c0c78cc949f7fe20c7b8d80_upd_tinymu.toiletlid.v1.bin?GalaxyAccessKeyId=5721718224520&Expires=1515580265000&Signature=MQPqgPO3XfrRZYGOP1NRkF6BXMs=
#define SERVER_PORT 443
//#define SERVER_NAME "cnbj0.fds.api.xiaomi.com"
//#define SERVER_NAME "111.206.200.99"
#define SERVER_NAME "cdn.cnbj0e.fds.api.mi-img.com"
//#define SERVER_NAME "36.250.240.133"
//#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define GET_REQUEST "GET "\
					"/miio_fw/b53ff7643c0c78cc949f7fe20c7b8d80_upd_tinymu.toiletlid.v1.bin?GalaxyAccessKeyId=5721718224520&Expires=1515580265000&Signature=MQPqgPO3XfrRZYGOP1NRkF6BXMs="\
					" HTTP/1.1\r\n"\
					"host: cdn.cnbj0e.fds.api.mi-img.com\r\n"\
					"Accept: */*\r\n\r\n"

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

#define HTTP_HEAD_SIZE	1500
#define MIN(a,b) ( (a) < (b) ? (a) : (b) )

typedef struct{
	//运行内部参数
	size_t content_len;
	size_t body_processed;
	/*header*/
	uint8_t* phead;
	uint16_t head_len;
}tcpc_httpc_t;

static void my_debug( void *ctx, int level,
                      const char *file, int line, const char *str )
{
    ((void) level);
    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

static int tcpc_httpc_dnld_on_data(tcpc_httpc_t* httpc, uint16_t pkt_len, uint8_t* pkt_ptr)
{
	int ret = pkt_ptr;
//	LOG_DEBUG("rec: %s, buf_len: %d\r\n", pkt_ptr, pkt_len);
	//add for http header recv when the header is bigger than one packet
	if(0 == httpc->content_len){//try to find the whole head
		char* p;

		if(NULL == httpc->phead)
		{
			p = strstr((char*)pkt_ptr, "\r\n\r\n");//找到头部结束位置
			if(p){
				httpc->phead = (uint8_t*)malloc(HTTP_HEAD_SIZE);
				if(httpc->phead == NULL)
					goto close_exit;
				memcpy(httpc->phead, pkt_ptr, pkt_len);
				httpc->head_len = (uint32_t)p - (uint32_t)pkt_ptr;
			}

			if(0 != memcmp(pkt_ptr, "HTTP/1.1 200 OK", sizeof("HTTP/1.1 200 OK")-1) &&
			    0 != memcmp(pkt_ptr, "HTTP/1.0 200 OK", sizeof("HTTP/1.0 200 OK")-1)){
				pkt_ptr[pkt_len] = '\0';
				LOG_WARN("dnld:Wrong resp %s\r\n", pkt_ptr);
				goto close_exit;
			}
			LOG_INFO("dnld:Resp 200 OK.\r\n");
		}else{
			if((httpc->head_len + pkt_len) > HTTP_HEAD_SIZE){
				LOG_WARN("dnld:size big than header.\r\n");//todo
				free(httpc->phead);
				httpc->phead = NULL;
				goto close_exit;
			}
			memcpy(httpc->phead + httpc->head_len, pkt_ptr, pkt_len);
			httpc->head_len += pkt_len;
			p = strstr((char*)httpc->phead, "\r\n\r\n");//找到头部结束位置
			if((char *)NULL == p){
				if(httpc->head_len >= HTTP_HEAD_SIZE){
					LOG_WARN("dnld:Header not found.\r\n");
					free(httpc->phead);
					httpc->phead = NULL;
					goto close_exit;
				}
				return 0;
			}
			pkt_ptr = httpc->phead;
			pkt_len = httpc->head_len;
		}
	}
	if(0 == httpc->content_len){//must have found the head, and try to get content_len
		char* p;

		if(0 != memcmp(pkt_ptr, "HTTP/1.1 200 OK", sizeof("HTTP/1.1 200 OK")-1)){
			pkt_ptr[sizeof("HTTP/1.x 200 ")-1] = '\0';
			LOG_ERROR("HTTP resps:%s", (const char*)pkt_ptr);
			ret = -1;
			goto err_close_exit;
		}

		LOG_INFO("Httpc:Resp 200 OK.\r\n");

		if(NULL == (p = strstr((char*)pkt_ptr, "Content-Length:")) ||
		   0 == (httpc->content_len = atoi(p + sizeof("Content-Length:")))){
			LOG_ERROR("Content-Length err.");
			ret = -2;
			goto err_close_exit;
		}

		LOG_INFO("Httpc:Content-Length:%lu\r\n", httpc->content_len);

		//找到头部结束位置
		p = strstr((char*)pkt_ptr, "\r\n\r\n");
		if(NULL == p){
			LOG_ERROR("Header err.");
			ret = -3;
			goto err_close_exit;
		}
		p += 4;	//指向body

		//打开流

		pkt_len -= (p - (char*)pkt_ptr);
		pkt_ptr = (uint8_t*)p;
	}


	pkt_len = MIN(pkt_len, httpc->content_len - httpc->body_processed);
    LOG_DEBUG("==>have download :%lu\r",(httpc->body_processed * 100 / httpc->content_len));

	//写入

	httpc->body_processed += pkt_len;
	if(httpc->body_processed >= httpc->content_len){
		LOG_WARN("Httpc:Done(%ubytes).\r\n", (uint32_t)httpc->body_processed);
		ret = 0;
		goto close_exit;
	}
	return ret;

err_close_exit:
//	httpc->dnld_if->error(httpc->up_dn_ctx, (void*)httpc->last_msg);

//write_err_exit:

//open_err_exit:
	LOG_ERROR("Httpc:err,exit.\r\n");

close_exit:
	return ret;
}

int main( void )
{
    int ret = 0;

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

    LOG_DEBUG( " ***tls handshake ok***\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n",
    					mbedtls_ssl_get_version( &ssl ), mbedtls_ssl_get_ciphersuite( &ssl ) );

	if( ( ret = mbedtls_ssl_get_record_expansion( &ssl ) ) >= 0 )
		LOG_DEBUG( "    [ Record expansion is %d ]\n", ret );
	else
		LOG_DEBUG( "    [ Record expansion is unknown (compression) ]\n" );


	/*
	 * 6. write
	 */
	char req_buf[] = GET_REQUEST;
	LOG_INFO( " now, writing...\n\r%s\r\n", req_buf );
	if( ( ret = mbedtls_ssl_write( &ssl, (const unsigned char *)req_buf, strlen(req_buf) ) ) < 0 )
	{
		LOG_ERROR("tls: write failed ,ret is -0x%x.\n\r",-ret);
		goto exit;
	}


    /*
     * 7. read
     */
    //: mbedtls_ssl_read()，return n:n>=0成功读取到的数据,<0:read error

    uint8_t buf[1540];
    uint16_t buf_len;
    uint32_t rec_len = 0;

    tcpc_httpc_t httpc;
    memset(&httpc, 0x00, sizeof(tcpc_httpc_t));
    while(1){

		ret = mbedtls_ssl_read( &ssl, buf, sizeof(buf));
		rec_len += ret;
//		LOG_DEBUG("trying to read, ret: %d, rec_len: %d\r\n", ret, rec_len);
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
			ret = tcpc_httpc_dnld_on_data(&httpc, buf_len, buf);
			if(ret == 0){
				goto done;
			}else if(ret < 0){
				goto exit;
			}
		}
    }

	return( ret );
exit:
	LOG_DEBUG("error byebye!");
done:
//	LOG_WARN("tls:connect to server failed.\n\r");
	mbedtls_net_free( &server_fd );
#if defined(MBEDTLS_X509_CRT_PARSE_C)
	mbedtls_x509_crt_free( &cacert );
#endif
	mbedtls_ssl_free( &ssl );
	mbedtls_ssl_config_free( &conf );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );


#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif
