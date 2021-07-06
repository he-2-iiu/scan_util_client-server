#ifndef SCAN_UTIL_CLIENT_SERVER_SCANNER_H
#define SCAN_UTIL_CLIENT_SERVER_SCANNER_H

#include <cstddef>

enum ScannerResultsTypes
{
  Searched,
  Errors,
  JsDetects,
  UnixDetects,
  MacosDetects,
  DurationS,
  DurationMs,
  DurationUs,
  ResultsTypesNum
};

/*struct ScannerResults
{
  size_t n_searched;
  size_t n_errors;
  size_t n_js_detects;
  size_t n_unix_detects;
  size_t n_macos_detects;
  size_t duration_s;
  size_t duration_ms;
  size_t duration_us;
};*/

#define SCANNER_ERROR_NO_DIR 2
#define SCANNER_ERROR_NO_PERMISSIONS 1
#define SCANNER_SUCCESS 0

int scan_directory(const char* directory_path, size_t results[]);

#endif /*SCAN_UTIL_CLIENT_SERVER_SCANNER_H*/
