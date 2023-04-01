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
  int client_socket =
      accept(s, (struct sockaddr*)(&server_address), (socklen_t*)&len);
  printf("accept with %d\n", client_socket);
  while (1) {
    char buf[1024] = {0};
    int read_len = recv(client_socket, buf, 1024, 0);

    if (read_len == 0) {
      continue;
    }

    printf("Message received as %s\n", buf);

    int send_len = send(client_socket, "hello!!", 8, 0);

    printf("Message sent\n");
  }

  return 0;
}
