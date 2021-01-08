// SQLight, tiny MySQL C++11 client. Based on code by Ladislav Nevery.
// - rlyeh, 2013. zlib/libpng licensed

#ifndef __SQLIGHT_HPP
#define __SQLIGHT_HPP

#pragma once

#include <map>
// #include <mutex>
#include <string>
#include <vector>

#include "ca_bundle.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_v.h"
#include "mbedtls/net_f.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#define SQLIGHT_VERSION "1.0.0" // (2015/09/10) Initial semantic versioning adherence

namespace sq
{
    static void my_debug(void *ctx, int level,
                         const char *file, int line,
                         const char *str) {
      const char *p, *basename;
      (void) (ctx);

      /* Extract basename from file */
      for (p = basename = file; *p != '\0'; p++)
        if (*p == '/' || *p == '\\')
          basename = p + 1;

      mbedtls_printf("%s:%04d: |%d| %s", basename, line, level, str);
    }

    class light
    {
    public:
        enum : unsigned {
            CLIENT_LONG_PASSWORD = 1,           /* New more secure passwords */
            CLIENT_FOUND_ROWS = 2,              /* Found instead of affected rows */
            CLIENT_LONG_FLAG = 4,               /* Get all column flags */
            CLIENT_CONNECT_WITH_DB = 8,         /* One can specify db on connect */
            CLIENT_NO_SCHEMA = 16,              /* Don't allow database.table.column */
            CLIENT_COMPRESS = 32,               /* Can use compression protocol */
            CLIENT_ODBC = 64,                   /* Odbc client */
            CLIENT_LOCAL_FILES = 128,           /* Can use LOAD DATA LOCAL */
            CLIENT_IGNORE_SPACE = 256,          /* Ignore spaces before '(' */
            CLIENT_PROTOCOL_41 = 512,           /* New 4.1 protocol */
            CLIENT_INTERACTIVE = 1024,          /* This is an interactive client */
            CLIENT_SSL = 0x0800,                  /* Switch to SSL after handshake */
            CLIENT_IGNORE_SIGPIPE = 4096,       /* IGNORE sigpipes */
            CLIENT_TRANSACTIONS = 8192,         /* Client knows about transactions */
            CLIENT_RESERVED = 16384,            /* Old flag for 4.1 protocol */
            CLIENT_SECURE_CONNECTION = 32768,   /* New 4.1 authentication */
            CLIENT_MULTI_STATEMENTS = 65536,    /* Enable/disable multi-stmt support */
            CLIENT_MULTI_RESULTS = 131072       /* Enable/disable multi-results */
        //  CLIENT_REMEMBER_OPTIONS = (((ulong) 1) << 31)
        };

        enum : unsigned char {
            FIELD_TYPE_BIT = 16,
            FIELD_TYPE_BLOB = 252,
            FIELD_TYPE_DATE = 10,
            FIELD_TYPE_DATETIME = 12,
            FIELD_TYPE_DECIMAL = 0,
            FIELD_TYPE_DOUBLE = 5,
            FIELD_TYPE_ENUM = 247,
            FIELD_TYPE_FLOAT = 4,
            FIELD_TYPE_GEOMETRY = 255,
            FIELD_TYPE_INT24 = 9,
            FIELD_TYPE_LONG = 3,
            FIELD_TYPE_LONG_BLOB = 251,
            FIELD_TYPE_LONGLONG = 8,
            FIELD_TYPE_MEDIUM_BLOB = 250,
            FIELD_TYPE_NEW_DECIMAL = 246,
            FIELD_TYPE_NEWDATE = 14,
            FIELD_TYPE_NULL = 6,
            FIELD_TYPE_SET = 248,
            FIELD_TYPE_SHORT = 2,
            FIELD_TYPE_STRING = 254,
            FIELD_TYPE_TIME = 11,
            FIELD_TYPE_TIMESTAMP = 7,
            FIELD_TYPE_TINY = 1,
            FIELD_TYPE_TINY_BLOB = 249,
            FIELD_TYPE_VAR_STRING = 253,
            FIELD_TYPE_VARCHAR = 15,
            FIELD_TYPE_YEAR = 13
        };

        typedef unsigned char  byte;
        typedef unsigned short dword;

         light();
        ~light();

        bool connect( const std::string &host = "127.0.0.1", unsigned port = 3306,
                const std::string &user = "root", const std::string &password = "root" );
        bool reconnect();
        void disconnect();
        // bool is_connected();

        typedef void (*callback3) (void *userdata, int w, int h, const char **map );

        bool test( const std::string &query );
        bool exec( const std::string &query, sq::light::callback3 cb, void *userdata = (void*)0 );

        std::string json( const std::string &query );
        bool json( const std::string &query, std::string &result );

        void init_tls()
        {
            LL_INFO("(DCMMC) begin init_tls");
            // (DCMMC) debug mbedtls
            mbedtls_debug_set_threshold(0);
            mbedtls_net_init(&server_fd);
            mbedtls_ssl_init(&ssl);
            mbedtls_ssl_config_init(&conf);
            memset(&saved_session, 0, sizeof(mbedtls_ssl_session));
            mbedtls_ctr_drbg_init(&ctr_drbg);
#if defined(MBEDTLS_X509_CRT_PARSE_C)
            mbedtls_x509_crt_init(&cacert);
            mbedtls_x509_crt_init(&clicert);
            mbedtls_pk_init(&pkey);
#endif

#if defined(MBEDTLS_DEBUG_C)
            mbedtls_debug_set_threshold(0);
#endif

            mbedtls_entropy_init(&entropy);
            /*
            * 0. Initialize the RNG and the session data
            */
            if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                           (const unsigned char *) pers,
                                           strlen(pers))) != 0) {
                LL_CRITICAL(" mbedtls_ctr_drbg_seed returned -%#x", -ret);
                throw std::runtime_error("mbedtls_ctr_drbg_seed failed");
            }

            /*
            * 1. Load the trusted CA
            */
#if defined(MBEDTLS_X509_CRT_PARSE_C)
            ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mozilla_ca_bundle,
                    sizeof(mozilla_ca_bundle));
            if (ret < 0) {
                throw std::runtime_error("mbedtls_x509_crt_parse failed");
            }
#endif /* MBEDTLS_X509_CRT_PARSE_C */

      /*
       * 2. Start the connection
       */

      std::string port_str = std::to_string(port);
      LL_TRACE("connecting over TCP: %s:%s...", host.c_str(), port_str.c_str());

      if ((ret = mbedtls_net_connect(&server_fd, host.c_str(), port_str.c_str(),
                                     MBEDTLS_NET_PROTO_TCP)) != 0) {
        throw std::runtime_error("mbedtls_net_connect returned");
      }

      // (DCMMC) MySQL 在每次建立起 TCP 回话的时候就会发送 HandshakeV10 到 client
      // MBED TLS 的 socket file descriptor 和 sqlight 的 sq::light::s 必须共享
      // 同一个 fd，不然的话 TLS 创建回话时，client 发握手会收到 MySQL 发来的错误的响应
      // (HandshakeV10 而不是 TLS server hello)
      this->s = server_fd.fd;
      LL_INFO("(DCMMC) set global socket fd=%d", this->s);

            LL_INFO("(DCMMC) finish init_tls");
        }

        void connect_tls(std::string &host, unsigned port) {
            std::string port_str = std::to_string(port);

  ret = mbedtls_net_set_block(&server_fd);
  if (ret != 0) {
    throw std::runtime_error("net_set_(non)block()");
  }

  /*
   * 3. Setup stuff
   */
  LL_TRACE("Setting up the SSL/TLS structure...");

  if ((ret = mbedtls_ssl_config_defaults(&conf,
                                         MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
    throw std::runtime_error("mbedtls_ssl_config_defaults");
  }

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
  if ((ret = mbedtls_ssl_conf_max_frag_len(&conf, MBEDTLS_SSL_MAX_FRAG_LEN_NONE)) != 0) {
    throw std::runtime_error("mbedtls_ssl_conf_max_frag_len");
  }
#endif

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg(&conf, sq::my_debug, NULL);

  mbedtls_ssl_conf_read_timeout(&conf, 0);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
  mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
#endif

#if defined(MBEDTLS_SSL_RENEGOTIATION)
  mbedtls_ssl_conf_renegotiation(&conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
#endif

  if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
    throw std::runtime_error("mbedtls_ssl_setup");
  }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
  if ((ret = mbedtls_ssl_set_hostname(&ssl, host.c_str())) != 0) {
    throw std::runtime_error("mbedtls_ssl_set_hostname");
  }
#endif

  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv,
          mbedtls_net_recv_timeout);

  /*
   * 4. Handshake
   */
  LL_TRACE("Performing the SSL/TLS handshake");

  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {

#if defined(MBEDTLS_X509_CRT_PARSE_C)
      LL_TRACE("Verifying peer X.509 certificate...");
      if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
        LL_CRITICAL("X.509 certificate failed to verify");
        char temp_buf[1024];
        if (mbedtls_ssl_get_peer_cert(&ssl) != NULL) {
          LL_CRITICAL("Peer certificate information");
          mbedtls_x509_crt_info((char *) temp_buf, sizeof(temp_buf) - 1, "|-", mbedtls_ssl_get_peer_cert(&ssl));
          mbedtls_printf("%s\n", temp_buf);
        } else {
          LL_CRITICAL("mbedtls_ssl_get_peer_cert returns NULL");
        }
      } else {
        LL_TRACE("X.509 Verifies");
      }
#endif /* MBEDTLS_X509_CRT_PARSE_C */
      if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        LL_CRITICAL("Unable to verify the server's certificate.");
      }

      // (DCMMC) debug only!!!
    if (1)
    {
        ret = -ret;
        // error code reference: mbedtls/ssh.h
        LL_CRITICAL("(DCMMC) mbedtls_ssl_handshake failed, ret=0x%02x%02x",
                ret >> 8, ret & 0xff);
        LL_INFO("exempt handshake error for localhost");
        break;
    }
      else
      {
        LL_CRITICAL("(DCMMC) mbedtls_ssl_handshake failed.");
          throw std::runtime_error("mbedtls_ssl_handshake failed.");
      }
    }
  }

  LL_TRACE("Hand shake succeeds: ");
  LL_TRACE("[%s, %s]", mbedtls_ssl_get_version(&ssl), mbedtls_ssl_get_ciphersuite(&ssl));

  if ((ret = mbedtls_ssl_get_record_expansion(&ssl)) >= 0) {
    LL_TRACE("Record expansion is [%d]", ret);
  } else
    LL_TRACE("Record expansion is [unknown (compression)]");

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
  LL_TRACE("Maximum fragment length is [%u]",
           (unsigned int) mbedtls_ssl_get_max_frag_len(&ssl));
#endif
        }

        int send_tls(char *data, size_t length) {
            int ret = 0;
          for (int written = 0, frags = 0; written < length; written += ret, frags++) {
            while ((ret = mbedtls_ssl_write(&ssl,
                                            reinterpret_cast<const unsigned char *>(data) + written,
                                            length - written)) <= 0) {
              if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                  ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                mbedtls_printf("  mbedtls_ssl_write returned -%#x", -ret);
                throw std::runtime_error("mbedtls_ssl_write");
              }
            }
          }
          return ret;
        }

        int recv_tls(char *buffer, size_t length) {
            int received = 0;
            while (true) {
                /*
                return the number of bytes read, or 0 for EOF, or
                MBEDTLS_ERR_SSL_WANT_READ or MBEDTLS_ERR_SSL_WANT_WRITE, or
                MBEDTLS_ERR_SSL_CLIENT_RECONNECT (see below), or another negative
                error code.
                */
                int cur_ret = mbedtls_ssl_read(&ssl, (unsigned char *) buffer + received, length - received);

                LL_TRACE("mbedtls_ssl_read returns %d", cur_ret);

                if (cur_ret == MBEDTLS_ERR_SSL_WANT_READ ||
                    cur_ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                  continue;

                if (cur_ret < 0) {
                  switch (cur_ret) {
                    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:LL_CRITICAL(" connection was closed gracefully");
                      throw std::runtime_error("connection was closed gracefully");
                    case MBEDTLS_ERR_NET_CONN_RESET:LL_CRITICAL(" connection was reset by peer");
                      throw std::runtime_error("connected reset");
                    default:LL_CRITICAL(" mbedtls_ssl_read returned -0x%x", -cur_ret);
                      throw std::runtime_error("mbedtls_ssl_read returned non-sense");
                  }
                }
                else {
                    if (cur_ret == 0)
                        break;
                    received += cur_ret;
                }
            } // while (true)
            if (received == length) {
                LL_CRITICAL("(DCMMC) receiving buffer (%zu bytes) is not big enough", length);
            }
            return received;
        }

    protected:
        bool connected;
        std::string host, user;
        unsigned port;
        std::vector<unsigned char> pass;

        int s, i;
        unsigned ret, no;

        std::vector<char> buf;
        char *b, *d;

        // std::mutex mutex;

        bool open();
        bool sends( const std::string &command );
        bool recvs( void *userdata, void* onvalue, void* onfield, void *onsep );
        bool fail( const char *error = 0, const char *title = 0 );
        bool acquire();
        void release();
    private:
        // (DCMMC) MySQL cap flags
        int capability_flags = 0;
        bool use_tls = false;
        const char *pers = "Town-Crier";
        mbedtls_net_context server_fd;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_ssl_session saved_session;
#if defined(MBEDTLS_X509_CRT_PARSE_C)
        uint32_t flags;
        mbedtls_x509_crt cacert;
        mbedtls_x509_crt clicert;
        mbedtls_pk_context pkey;
#endif
    };
}

#endif
