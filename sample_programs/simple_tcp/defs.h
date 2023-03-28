#ifndef DEFS_H_
#define DEFS_H_

#include <netinet/ip.h>
#include <arpa/inet.h>

struct sockaddr_in get_default() {
  struct sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(80);
  server_address.sin_addr.s_addr = inet_addr("10.0.1.100");

  return server_address;
}

#endif
