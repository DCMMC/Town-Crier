#ifndef SRC_ENCLAVE_SCRAPERS_SQL_SCRAPERS_H_
#define SRC_ENCLAVE_SCRAPERS_SQL_SCRAPERS_H_

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


using std::string;

enum sql_error {
  SQL_HTTP_SUCCESS = 0, /* http request success */
  SQL_INVALID,          /* Invalid Parameters passed to the function*/
  SQL_HTTP_ERROR,         /* HTTP request failed */
  SQL_INTERNAL_ERR,
};

class SQLScraper : Scraper {
 private:
  static const string HOST;
  static const string PORT;
  static const string URL;
 public:
  const uint32_t MAX_RESP_LEN = 1024;
  err_code handle(const uint8_t *req, size_t data_len, string *resp_data);
  err_code handleEncryptedQuery(const uint8_t *data, size_t data_len, string *resp_data);
  err_code handle(const uint8_t *req, size_t data_len, int *resp_data);

 private:
  sql_error get_sql_result(const string &sql_code, string &result);
};

#endif  // SRC_ENCLAVE_SCRAPERS_SQL_SCRAPERS_H_

