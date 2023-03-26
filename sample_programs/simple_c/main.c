#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

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

  /* Test segfault. */
  buf[1000000] = 1;

  int ret = kill(pid, SIGKILL);

  printf("ret = %d\n", ret);

  for(;;) {}

  return 0;
}
