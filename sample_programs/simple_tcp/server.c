#include <stdio.h>
#include <stdlib.h>

#include "defs.h"

int main() {
  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct sockaddr_in server_address = get_default();

  int bind_status =
      bind(s, (struct sockaddr*)(&server_address), sizeof(server_address));
  int listen_status = listen(s, 0);
  printf("got socket %d with bind status %d and listen status %d\n", s,
         bind_status, listen_status);

  struct sockaddr_in client_address;
  socklen_t len;
  int accept_status = accept(s, (struct sockaddr*)(&client_address), &len);

  printf("accepted %d\n", accept_status);

  return 0;
}
