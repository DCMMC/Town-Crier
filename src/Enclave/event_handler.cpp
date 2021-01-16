//
// Copyright (c) 2016-2018 by Cornell University.  All Rights Reserved.
//
// Permission to use the "TownCrier" software ("TownCrier"), officially
// docketed at the Center for Technology Licensing at Cornell University
// as D-7364, developed through research conducted at Cornell University,
// and its associated copyrights solely for educational, research and
// non-profit purposes without fee is hereby granted, provided that the
// user agrees as follows:
//
// The permission granted herein is solely for the purpose of compiling
// the TownCrier source code. No other rights to use TownCrier and its
// associated copyrights for any other purpose are granted herein,
// whether commercial or non-commercial.
//
// Those desiring to incorporate TownCrier software into commercial
// products or use TownCrier and its associated copyrights for commercial
// purposes must contact the Center for Technology Licensing at Cornell
// University at 395 Pine Tree Road, Suite 310, Ithaca, NY 14850; email:
// ctl-connect@cornell.edu; Tel: 607-254-4698; FAX: 607-254-5454 for a
// commercial license.
//
// IN NO EVENT SHALL CORNELL UNIVERSITY BE LIABLE TO ANY PARTY FOR
// DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES,
// INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF TOWNCRIER AND ITS
// ASSOCIATED COPYRIGHTS, EVEN IF CORNELL UNIVERSITY MAY HAVE BEEN
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// THE WORK PROVIDED HEREIN IS ON AN "AS IS" BASIS, AND CORNELL
// UNIVERSITY HAS NO OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES,
// ENHANCEMENTS, OR MODIFICATIONS.  CORNELL UNIVERSITY MAKES NO
// REPRESENTATIONS AND EXTENDS NO WARRANTIES OF ANY KIND, EITHER IMPLIED
// OR EXPRESS, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, OR THAT THE USE
// OF TOWNCRIER AND ITS ASSOCIATED COPYRIGHTS WILL NOT INFRINGE ANY
// PATENT, TRADEMARK OR OTHER RIGHTS.
//
// TownCrier was developed with funding in part by the National Science
// Foundation (NSF grants CNS-1314857, CNS-1330599, CNS-1453634,
// CNS-1518765, CNS-1514261), a Packard Fellowship, a Sloan Fellowship,
// Google Faculty Research Awards, and a VMWare Research Award.
//

#include "event_handler.h"
#include <string>
#include <inttypes.h>
// (DCMMC) debug
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "scrapers/scrapers.h"
#include "scrapers/sql_scrapers.h"
#include "scrapers/yahoo_yql_stock.h"
#include "scrapers/Scraper.h"
#include "scrapers/flight.h"
#include "scrapers/error_codes.h"
#include "scrapers/stock_ticker.h"
#include "scrapers/ups_tracking.h"
#include "scrapers/steam2.h"
#include "scrapers/coinmarketcap.h"
#include "scrapers/bitcoinfees.h"
#include "scrapers/current_weather.h"
#include "scrapers/wolfram.h"
#include "eth_transaction.h"
#include "eth_abi.h"
#include "Enclave_t.h"
#include "external/keccak.h"
#include "Constants.h"
#include "time.h"
#include "log.h"

#include "hybrid_cipher.h"
#include "env.h"

// (DCMMC) test for sqlight
#include "external/sqlight.hpp"

// (DCMMC) debug
// int ocall_print_string_debug(const char *str) {
//   int ret = printf("%s", str);
//   fflush(stdout);
//   return ret;
// }

int debug_sgx(const char *fmt, ...)
{
    int ret = 0;
    va_list ap;
    char buf[BUFSIZ] = {'\0'};
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);

    ocall_print_string(&ret, buf);
    return ret;
}

int debug_mysql(const char *host, unsigned int port,
        const char *user, const char *pass)
{
    // (DCMMC) test sqlight
    bool ret = true;
    LL_DEBUG("DCMMC: test sqlight");
    sq::light sql;
    // if (!sql.connect("172.17.0.1", 3306, "root", "97294597"))
    if (!sql.connect(host, port, user, pass))
        LL_DEBUG("DCMMC: connection to database failed");
    else
    {
        std::string input = "show variables like '%%ssl%%';";
        LL_INFO("(DCMMC) test mysql query: %s", input.c_str());
        std::string result;
        ret = sql.json(input, result);
        if (ret)
            LL_DEBUG("DCMMC: sqlight return=%s", result.c_str());
        else
            LL_DEBUG("DCMMC: sqlight exec failed.");

        std::string sql1 = "CREATE DATABASE IF NOT EXISTS test_db;";
        std::string sql2 = "USE test_db;";
        std::string sql3 = "DROP TABLE IF EXISTS tb_courses;";
        std::string sql4 = "CREATE TABLE tb_courses (course_id INT NOT NULL AUTO_INCREMENT, course_name CHAR(40) NOT NULL, course_grade FLOAT NOT NULL, course_info CHAR(100) NULL, PRIMARY KEY(course_id));";
        std::string sql5 = "SELECT * FROM tb_courses;";
        std::string sql6 = "INSERT INTO tb_courses (course_id,course_name,course_grade,course_info) VALUES(1,'Network',3,'Computer Network');";
        std::string sql7 = "SELECT * FROM tb_courses;";
        ret = sql.json(sql1, result);
        LL_INFO("(DCMMC) result of sql1:\n%s\n", result.c_str());
        ret = sql.json(sql2, result);
        LL_INFO("(DCMMC) result of sql2:\n%s\n", result.c_str());
        ret = sql.json(sql3, result);
        LL_INFO("(DCMMC) result of sql3:\n%s\n", result.c_str());
        ret = sql.json(sql4, result);
        LL_INFO("(DCMMC) result of sql4:\n%s\n", result.c_str());
        ret = sql.json(sql5, result);
        LL_INFO("(DCMMC) result of sql5:\n%s\n", result.c_str());
        ret = sql.json(sql6, result);
        LL_INFO("(DCMMC) result of sql6:\n%s\n", result.c_str());
        ret = sql.json(sql7, result);
        LL_INFO("(DCMMC) result of sql7:\n%s\n", result.c_str());
    }
    return ret == false ? 0 : -1;
}

/*
 * testing data
 *
 Request(app, 1, ['FJM273', pad(1492100100, 64)]);
 Request(app, 2, ['f68d2a32cf17b1312c6db3f236a38c94', '4c9f92f6ec1e2a20a1413d0ac1b867a3', '32884794', pad(1456380265, 64), pad(1, 64), 'Portal']);
 Request(app, 3, ['GOOG', pad(1262390400,64)]);;
 Request(app, 4, ['1ZE331480394808282']);
 Request(app, 5, ['bitcoin']);

 (DCMMD) 为了适配其他类型的请求（比如 SQL 查询），主要就是更改这个文件
 RequestType 在 src/Common/Constants.h 中定义
 */
int handle_request(int nonce,
        uint64_t id,
        uint64_t type,
        const uint8_t *data,
        size_t data_len,
        uint8_t *raw_tx,
        size_t *raw_tx_len) {
    int ret = 0;
    try {
        string tc_address = getContractAddress();
        LL_DEBUG("serving tc address: %s", tc_address.c_str());

        int ret = do_handle_request(nonce, id, type, data, data_len, raw_tx, raw_tx_len);
        return ret;
    }
    catch (const std::exception &e) {
        LL_CRITICAL("exception while handling request: %s", e.what());
    }
    catch (...) {
        LL_CRITICAL("unknown error while handling request");
    }

    return TC_INTERNAL_ERROR;
}

int do_handle_request(int nonce,
        uint64_t id,
        uint64_t type,
        const uint8_t *data,
        size_t data_len,
        uint8_t *raw_tx,
        size_t *raw_tx_len) {
    bytes resp_data;
    int error_flag = 0;

    switch (type) {
        case TYPE_GENERIC_SQL_LOCALHOST8443:
            {
                LL_INFO("DCMMC: SQL start!\n");
                SQLScraper sql_scrapers;
                string result;
                switch (sql_scrapers.handle(data, data_len, &result)) {
                    case UNKNOWN_ERROR:
                    case WEB_ERROR:
                        LL_INFO("DCMMC: SQL TC_INTERNAL_ERROR\n");
                        error_flag = TC_INTERNAL_ERROR;
                        break;
                    case INVALID_PARAMS:
                        LL_INFO("DCMMC: SQL TC_INPUT_ERROR\n");
                        error_flag = TC_INPUT_ERROR;
                        break;
                    case NO_ERROR:
                        LL_INFO("(DCMMC) SQLScraper returned: %s\n", result.c_str());
                        resp_data.insert(resp_data.end(), result.begin(), result.end());
                        break;
                    default:
                        error_flag = TC_ERR_FLAG_INVALID_INPUT;
                        break;
                }
                break;
            }
            /*
               case TYPE_ENCRYPT_TEST: {
               HybridEncryption dec_ctx;
               ECPointBuffer tc_pubkey;
               dec_ctx.queryPubkey(tc_pubkey);

               string cipher_b64(data, data + data_len);
               hexdump("encrypted query: ", data, data_len);

               try {
               HybridCiphertext cipher = dec_ctx.decode(cipher_b64);
               vector<uint8_t> cleartext;
               dec_ctx.hybridDecrypt(cipher, cleartext);
               hexdump("decrypted message", &cleartext[0], cleartext.size());

            // decrypted message is the base64 encoded data
            string encoded_message(cleartext.begin(), cleartext.end());
            uint8_t decrypted_data[cleartext.size()];
            int decrypted_data_len = ext::b64_pton(encoded_message.c_str(),
            decrypted_data, sizeof decrypted_data);

            if (decrypted_data_len == -1) {
            throw runtime_error("can't decode user message");
            }

            hexdump("decoded message", decrypted_data, (size_t) decrypted_data_len);
            }
            catch (const std::exception &e) {
            LL_CRITICAL("decryption error: %s. See dump above.", e.what());
            }
            catch (...) {
            LL_CRITICAL("unknown exception happened while decrypting. See dump above.");
            }

            return TC_INTERNAL_TEST;
            }
            */
        default :
            LL_CRITICAL("Unknown request type: %"
                    PRIu64, type);
            error_flag = TC_ERR_FLAG_INVALID_INPUT;
    }

    return form_transaction(nonce, id, type, data, data_len, error_flag, resp_data,
            raw_tx, raw_tx_len,
            // sign = true
            true);
}
