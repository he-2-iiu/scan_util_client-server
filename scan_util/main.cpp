#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SERVER_PATH ""

struct ScannerResponse
{
  size_t n_searched;
  size_t n_errors;
  size_t n_js_detects;
  size_t n_unix_detects;
  size_t n_macos_detects;
};

void print_scanning_results(ScannerResponse& results);

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

  /*
   * TODO: Add reading from server
   */

  ScannerResponse results{};

  print_scanning_results(results);

  close(socket_fd);

  return EXIT_SUCCESS;
}

void print_scanning_results(ScannerResponse& results)
{

}
