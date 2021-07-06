#include "socket_io.h"

#include <cstddef>
#include <unistd.h>

size_t fd_read(int fd, void* buf, size_t n)
{
  ssize_t rd{ 0 };
  size_t tr{ 0 };

  do {
    rd = read(fd, buf, n);
    if (rd < 0)
      return -1;
    if (rd == 0)
      break;
    tr += rd;
  } while (tr < n);
  return tr;
}

size_t fd_write(int fd, const void* buf, size_t n)
{
  ssize_t wr{ 0 };
  size_t tw{ 0 };
  do {
    wr = write(fd, buf, n);
    if (wr < 0)
      return -1;
    tw += wr;
  } while (tw < n);
  return tw;
}
