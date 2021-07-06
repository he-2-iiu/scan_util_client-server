#ifndef SCAN_UTIL_CLIENT_SERVER_SOCKET_IO_H
#define SCAN_UTIL_CLIENT_SERVER_SOCKET_IO_H

#include <cstddef>

size_t fd_read(int fd, void* buf, size_t n);

size_t fd_write(int fd, const void* buf, size_t n);

#endif /*SCAN_UTIL_CLIENT_SERVER_SOCKET_IO_H*/
