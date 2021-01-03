// (DCMMC) currently only support linux
#include <arpa/inet.h>  // inet_addr
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>  // close, write

enum { TCP_OK = 0, TCP_ERROR = -1, TCP_TIMEOUT = -2 };

// (DCMMC) untrusted functions
int ocall_connect(int *s, unsigned port, char *host)
{
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_pton(AF_INET, host, &addr.sin_addr);

  *s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  return connect(*s, (struct sockaddr *)&addr, sizeof(addr));
}

int ocall_close(int fp) { return close(fp); }

ssize_t ocall_recv(int socket, char *buffer, size_t length, int flags)
{
  return recv(socket, (void *)buffer, length, flags);
}

struct timeval as_timeval(double seconds)
{
  struct timeval tv;
  tv.tv_sec = (int)(seconds);
  tv.tv_usec = (int)((seconds - (int)(seconds)) * 1000000.0);
  return tv;
}

int ocall_select(int *sockfd, double timeout)
{
  // set up the file descriptor set
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(*sockfd, &fds);

  // set up the struct timeval for the timeout
  struct timeval tv = as_timeval(timeout);

  // wait until timeout or data received
  // if  tv = {n,m}, then select() waits up to n.m seconds
  // if  tv = {0,0}, then select() does polling
  // if &tv =  NULL, then select() waits forever
  int ret = select((*sockfd) + 1, &fds, NULL, NULL, &tv);
  return (ret == -1 ? (*sockfd) = -1, TCP_ERROR : ret == 0 ? TCP_TIMEOUT : TCP_OK);
}

// int ocall_select(int nfds, fd_set *readfds, fd_set *writefds,
//            fd_set *exceptfds, struct timeval *timeout)
// {
//     return select(nfds, readfds, writefds, exceptfds, timeout);
// }

ssize_t ocall_send(int socket, char *message, size_t length, int flags)
{
  return send(socket, (const void *)message, length, flags);
}

ssize_t ocall_write(int fildes, const void *buf, size_t nbyte)
{
  return write(fildes, buf, nbyte);
}
