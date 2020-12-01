// (DCMMC) SQL Scrapers 的核心实现
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstring>
#include <vector>
#include <cctype>

#include "Scraper.h"
#include "error_codes.h"
#include "Constants.h"
#include "tls_client.h"
#include "commons.h"
#include "hybrid_cipher.h"
#include "../log.h"
#include "scraper_utils.h"
#include "debug.h"

#include "sql_scrapers.h"

using std::string;

const string SQLScraper::HOST = "localhost";
const string SQLScraper::PORT = "8443";
const string SQLScraper::URL = "/execute_sql?sql=";

/*  The Data is structured as follows:
 *      0x00 - \infty: (string) raw SQL code
 */
err_code SQLScraper::handle(const uint8_t *req, size_t data_len, string *resp_data) {
  const string raw_sql_code(req, req + data_len);
  LL_INFO("Raw SQL code=%s", raw_sql_code.c_str());
  string result;
  sql_error ret = get_sql_result(raw_sql_code, result);

  switch (ret) {
    case SQL_INVALID:
      *resp_data = -1;
      return INVALID_PARAMS;

    case SQL_HTTP_ERROR:
      *resp_data = -1;
      return WEB_ERROR;

    case SQL_HTTP_SUCCESS:
      resp_data->clear();
      *resp_data = result;
      return NO_ERROR;
    case SQL_INTERNAL_ERR:
    default:
      return UNKNOWN_ERROR;
  }
}

err_code SQLScraper::handleEncryptedQuery(const uint8_t *req, size_t data_len, string *resp_data) {
    const string ciphertext(req, req + data_len);
    for (const char &c : ciphertext) {
        if (!std::isxdigit(c)) {
            LL_CRITICAL("Encrypted SQL Code must contains only hexadecimal numeric characters, ciphertext=%s", ciphertext.c_str());
            *resp_data = "ERROR";
            return INVALID_PARAMS;
        }
    }
  hexdump("Encrypted_data", req, data_len);
  string raw_sql_code;
  try {
    raw_sql_code = decrypt_query(req, data_len);
    LL_INFO("Decrypted raw SQL code: %s", raw_sql_code.c_str());
  }
  catch (const DecryptionException &e) {
    LL_CRITICAL("Can't decrypt: %s", e.what());
    return INVALID_PARAMS;
  }
  catch (...) {
    LL_CRITICAL("unknown error");
    return INVALID_PARAMS;
  }
  string result;
  sql_error ret = get_sql_result(raw_sql_code, result);

  switch (ret) {
    case SQL_INVALID:
      *resp_data = "ERROR";
      return INVALID_PARAMS;

    case SQL_HTTP_ERROR:
      *resp_data = "ERROR";
      return WEB_ERROR;

    case SQL_HTTP_SUCCESS:
      resp_data->clear();
      *resp_data = result;
      return NO_ERROR;
    case SQL_INTERNAL_ERR:
    default:
      return UNKNOWN_ERROR;
  }
}

sql_error SQLScraper::get_sql_result(const string &sql_code, string &result) {
    for (const char &c : sql_code) {
        if (!std::isalnum(c)) {
            LL_CRITICAL("SQL Code must be URL encoded, sql_code=%s", sql_code.c_str());
            return SQL_INVALID;
        }
    }
  const string request_get = this->URL + sql_code.c_str();
  std::vector<string> header;

  HttpRequest httpRequest(this->HOST, this->PORT, request_get, header, true);
  HttpsClient httpClient(httpRequest);

  try {
    HttpResponse resp = httpClient.getResponse();
    result = resp.getContent();
    LL_INFO("Result=%s", result.c_str());
    return SQL_HTTP_SUCCESS;
  }
  catch (std::runtime_error &e) {
    LL_CRITICAL("Https error: %s", e.what());
    LL_CRITICAL("Details: %s", httpClient.getError().c_str());
    httpClient.close();
    return SQL_HTTP_ERROR;
  }
}

err_code SQLScraper::handle(const uint8_t *req, size_t data_len, int *resp_data) {
    return NO_ERROR;
}

