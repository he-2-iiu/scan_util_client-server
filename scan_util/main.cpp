#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "../scan_service/scanner.h"

#define SERVER_PATH "/tmp/scan_service"

void print_scanning_results(ScannerResults& results);

int main(int argc, char* argv[])
{
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " [directory path]\n";
    exit(EXIT_FAILURE);
  }

  const char* message = argv[1];
  const int socket_fd{ socket(PF_LOCAL, SOCK_STREAM, 0) };
  if (socket_fd == -1) {
    std::cerr << "Socket creation error" << std::strerror(errno) << '\n';
    exit(EXIT_FAILURE);
  }
  const sockaddr_un name{ PF_LOCAL, SERVER_PATH };

  if ((connect(socket_fd, reinterpret_cast<const sockaddr*>(&name), SUN_LEN(&name))) == -1) {
    std::cerr << "Connect: " << std::strerror(errno) << '\n';
    close(socket_fd);
    exit(EXIT_FAILURE);
  }

  const size_t message_length = strlen(message) + 1;
  /*
   * TODO: Write in a loop to prevent errors
   */
  write(socket_fd, &message_length, sizeof(message_length));
  write(socket_fd, message, message_length);

  ScannerResults results{};
  int scanner_return_code;

  if (!read(socket_fd, &scanner_return_code, sizeof(scanner_return_code))) {
    std::cout << "Server closed connection\n";
    close(socket_fd);
    return EXIT_SUCCESS;
  }

  if (scanner_return_code == SCANNER_SUCCESS) {
    read(socket_fd, &results, sizeof(results));
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

void print_scanning_results(ScannerResults& results)
{
  std::cout << "====== Scan result ===========\n" <<
            "Processed files: " << results.n_searched << '\n' <<
            "JS detects: " << results.n_js_detects << '\n' <<
            "Unix detects: " << results.n_unix_detects << '\n' <<
            "macOS detects: " << results.n_macos_detects << '\n' <<
            "Errors: " << results.n_errors << '\n' <<
            "Execution time: " << std::fixed << std::setprecision(2) << results.duration_s << "s:" <<
            std::fixed << std::setprecision(2) << results.duration_ms << "ms:" <<
            std::fixed << std::setprecision(2) << results.duration_us << "us" << '\n' <<
            "==============================\n";
}
