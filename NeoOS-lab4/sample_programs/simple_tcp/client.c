#include <stdio.h>

#include "defs.h"

int main() {
  struct sockaddr_in server_address = get_default();

  int client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  int connect_status = connect(client, (struct sockaddr*)(&server_address),
                               sizeof(server_address));
  printf("got socket %d with connect status %d\n", client, connect_status);
}