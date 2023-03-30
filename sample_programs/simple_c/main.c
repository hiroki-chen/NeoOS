#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

/* A sample echoing program. */
int main() {
  printf("From user application:\n");
  printf("        .-\"\"\"\"\"-.\n");
  printf("      .'          '.\n");
  printf("     /   O      O   \\\n");
  printf("    :                :\n");
  printf("    |                |\n");
  printf("    : ',          ,' :\n");
  printf("     \\  '-......-'  /\n");
  printf("      '.          .'\n");
  printf("        '-......-'\n");

  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(80);
  server_address.sin_addr.s_addr = inet_addr("10.130.30.233");

  int bind_status =
      bind(s, (struct sockaddr*)(&server_address), sizeof(server_address));
  int listen_status = listen(s, 0);
  printf("got socket %d with bind status %d and listen status %d\n", s,
         bind_status, listen_status);

  size_t len = 0;
  int accept_result =
      accept(s, (struct sockaddr*)(&server_address), (socklen_t*)&len);
  printf("accept with %d\n", accept_result);
  while (1) {
  }

  return 0;
}
