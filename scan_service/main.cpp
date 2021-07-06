#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SERVER_PATH ""
#define EXIT_MESSAGE ""

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
    close(socket_fd);
    exit(EXIT_FAILURE);
  }

  listen(socket_fd, 5);

  size_t msg_len;
  char* msg;
  int client_socket_fd;
  for (;;) {
    client_socket_fd = accept(socket_fd, nullptr, nullptr);
    if (read(client_socket_fd, &msg_len, sizeof(msg_len)) == 0) {
      close(client_socket_fd);
      break;
    }

    msg = new char[msg_len];
    read(client_socket_fd, msg, msg_len);

    if (!strcmp(msg, EXIT_MESSAGE)) {
      close(client_socket_fd);
      delete[] msg;
      break;
    }

    /*
     * TODO: Add scanning and writing to client
     */

    delete[] msg;
    close(client_socket_fd);
  }

  close(socket_fd);
  unlink(SERVER_PATH);
  return EXIT_SUCCESS;
}