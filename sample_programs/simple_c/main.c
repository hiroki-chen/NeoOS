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

  char buf[100];
  getcwd(buf, sizeof(buf));
  printf("The current working directory is %s\n", buf);

  int pid = getpid();
  printf("pid is %d\n", pid);

  char* env = getenv("PATH");
  printf("path = %s\n", env);

  int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  struct sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(80);
  server_address.sin_addr.s_addr = inet_addr("10.0.1.100");

  int bind_status =
      bind(s, (struct sockaddr*)(&server_address), sizeof(server_address));
  int listen_status = listen(s, 0);
  printf("got socket %d with bind status %d and listen status %d\n", s,
         bind_status, listen_status);

  int client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  int connect_status = connect(client, (struct sockaddr*)(&server_address),
                               sizeof(server_address));
  printf("god socket %d with connect status %d\n", client, connect_status);

  for (;;) {
    char buf[10] = {0};
    scanf("%s", buf);
    printf("read %s\n", buf);
  }

  return 0;
}
