#include <iostream>
#include <iomanip>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "../scan_service/scanner.h"
#include "../scan_service/socket_io.h"

#define SERVER_PATH "/tmp/scan_service"

void print_scanning_results(const size_t results[]);

int main(int argc, char* argv[])
{
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " [directory path]\n";
    exit(EXIT_FAILURE);
  }

  const char* message = argv[1];
  const int socket_fd{ socket(PF_LOCAL, SOCK_STREAM, 0) };
  if (socket_fd == -1) {
    std::cerr << "Socket creation error" << strerror(errno) << '\n';
    exit(EXIT_FAILURE);
  }
  const sockaddr_un name{ PF_LOCAL, SERVER_PATH };

  if ((connect(socket_fd, reinterpret_cast<const sockaddr*>(&name), SUN_LEN(&name))) == -1) {
    std::cerr << "Connect: " << strerror(errno) << '\n';
    close(socket_fd);
    exit(EXIT_FAILURE);
  }

  const size_t message_length = strlen(message) + 1;

  fd_write(socket_fd, &message_length, sizeof(message_length));
  fd_write(socket_fd, message, message_length);

  size_t results[ScannerResultsTypes::ResultsTypesNum];
  int scanner_return_code;

  if (!fd_read(socket_fd, &scanner_return_code, sizeof(scanner_return_code))) {
    std::cout << "Server closed connection\n";
    close(socket_fd);
    return EXIT_SUCCESS;
  }

  if (scanner_return_code == SCANNER_SUCCESS) {
    fd_read(socket_fd, &results, sizeof(results));
    print_scanning_results(results);
  }

  if (scanner_return_code == SCANNER_ERROR_NO_DIR) {
    std::cerr << message << " does not exist\n";
  }

  if (scanner_return_code == SCANNER_ERROR_NO_PERMISSIONS) {
    std::cerr << "Not enough permissions to open " << message << '\n';
  }

  close(socket_fd);

  return EXIT_SUCCESS;
}

void print_scanning_results(const size_t results[])
{
  std::cout << "====== Scan result ===========\n" <<
            "Processed files: " << results[ScannerResultsTypes::Searched] << '\n' <<
            "JS detects: " << results[ScannerResultsTypes::JsDetects] << '\n' <<
            "Unix detects: " << results[ScannerResultsTypes::UnixDetects] << '\n' <<
            "macOS detects: " << results[ScannerResultsTypes::MacosDetects] << '\n' <<
            "Errors: " << results[ScannerResultsTypes::Errors] << '\n' <<
            "Execution time: " << std::fixed << std::setprecision(2) << results[ScannerResultsTypes::DurationS] << "s:" <<
            std::fixed << std::setprecision(2) << results[ScannerResultsTypes::DurationMs] << "ms:" <<
            std::fixed << std::setprecision(2) << results[ScannerResultsTypes::DurationUs] << "us" << '\n' <<
            "==============================\n";
}
