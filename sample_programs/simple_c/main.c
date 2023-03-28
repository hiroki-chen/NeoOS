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

  for (;;) {
    char buf[10] = {0};
    scanf("%s", buf);
    printf("read %s\n", buf);
  }

  return 0;
}
