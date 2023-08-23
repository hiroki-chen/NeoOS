#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>

/* A sample echoing program. */
int main(int argc, char* argv[], char* envp[]) {
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

  // unsigned long value;
  printf("AT_PLATFORM:\t\t%lx\n", getauxval(AT_PLATFORM));
  printf("AT_BASE:\t\t%lx\n", getauxval(AT_BASE));
  printf("AT_ENTRY:\t\t%lx\n", getauxval(AT_ENTRY));
  printf("AT_PHDR:\t\t%lx\n", getauxval(AT_PHDR));
  printf("AT_PHNUM:\t\t%lx\n", getauxval(AT_PHNUM));
  printf("AT_PAGESZ:\t\t%lx\n", getauxval(AT_PAGESZ));
  printf("AT_FLAGS:\t\t%lx\n", getauxval(AT_FLAGS));
  printf("AT_UID:\t\t\t%lx\n", getauxval(AT_UID));
  printf("AT_EUID:\t\t%lx\n", getauxval(AT_EUID));
  printf("AT_GID:\t\t\t%lx\n", getauxval(AT_GID));
  printf("AT_EGID:\t\t%lx\n", getauxval(AT_EGID));

  char* path = getenv("PATH");
  printf("path is %s\n", path);
  char* ld = getenv("LD_LIBRARY_PATH");
  printf("ld path is %s\n", ld);

  char str[512];
  printf("input something: ");
  fflush(stdout);
  scanf("%s\n", str);
  printf("The input is %s\n", str);

  return 0;
}
