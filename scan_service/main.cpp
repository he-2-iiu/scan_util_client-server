#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "scanner.h"
#include "socket_io.h"

#define SERVER_PATH "/tmp/scan_service"
#define EXIT_MESSAGE "CLOSE_CONNECTION"

int main()
{
  const int socket_fd{ socket(PF_LOCAL, SOCK_STREAM, 0) };
  if (socket_fd == -1) {
    std::cerr << "Socket creation error: " << std::strerror(errno) << '\n';
    exit(EXIT_FAILURE);
  }
  int option = 1;
  if ((setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char*>(&option), sizeof(option)) == -1)) {
    std::cerr << "Socket option setting error: " << std::strerror(errno) << '\n';
    close(socket_fd);
    exit(EXIT_FAILURE);
  }

  sockaddr_un name{ PF_LOCAL, SERVER_PATH };
  if ((bind(socket_fd, reinterpret_cast<const sockaddr*>(&name), SUN_LEN(&name))) == -1) {
    std::cerr << "Socket binding error: " << std::strerror(errno) << '\n';
    unlink(SERVER_PATH);
    close(socket_fd);
    exit(EXIT_FAILURE);
  }

  listen(socket_fd, 5);


  for (;;) {
    size_t msg_len;
    char* msg;
    int client_socket_fd;
    client_socket_fd = accept(socket_fd, nullptr, nullptr);
    if (fd_read(client_socket_fd, &msg_len, sizeof(msg_len)) == 0) {
      close(client_socket_fd);
      break;
    }

    msg = new char[msg_len];
    fd_read(client_socket_fd, msg, msg_len);

    if (!strcmp(msg, EXIT_MESSAGE)) {
      close(client_socket_fd);
      delete[] msg;
      break;
    }

    size_t results[ScannerResultsTypes::ResultsTypesNum];
    const int scanner_return_code{ scan_directory(msg, results) };

    fd_write(client_socket_fd, &scanner_return_code, sizeof(scanner_return_code));
    if (scanner_return_code == SCANNER_SUCCESS) {
      fd_write(client_socket_fd, &results, sizeof(results));
    }

    delete[] msg;
    close(client_socket_fd);
  }

  close(socket_fd);
  unlink(SERVER_PATH);
  return EXIT_SUCCESS;
}
