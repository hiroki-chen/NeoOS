/* Tests whether the syscall interfaces for filesystem manipulation are correct
 * and sane. */

#include <fcntl.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

int test_getdents64(const char *name) {
  DIR *dir;
  struct dirent *ent;

  // Open the root directory "/"
  dir = opendir(name);

  if (dir == NULL) {
    // Failed to open directory
    return -1;
  }

  // Read all directory entries
  while ((ent = readdir(dir)) != NULL) {
    // Print the name of the file or directory
    // printf("%s ", ent->d_name);
  }

  // Close the directory
  closedir(dir);

  return 0;
}

int test_stat(const char *filename) {
  // get information about the file using the stat() function
  struct stat file_stat;
  if (stat(filename, &file_stat) == -1) {
    return -1;
  }

  // print out the file's size in bytes
  printf("\n\t[+] File size: %lld bytes\n", (long long)file_stat.st_size);

  // print out the file's permissions in octal notation
  printf("\t[+] File permissions: %o\n", file_stat.st_mode & 0777);

  // print out the file's last modification time
  char time_str[80];
  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
           localtime(&file_stat.st_mtime));
  printf("\t[+] File last modified: %s\n", time_str);

  return 0;
}

int main() {
  int passed_suite = 0;
  int failed_suite = 0;

  printf("[-] testing `getdents64` for root directory `/`...");
  if (test_getdents64("/") != 0) {
    printf("\tfailed.\n");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf(
      "[-] testing `getdents64` for root directory `/foo` and should fail...");
  if (test_getdents64("/foo") == 0) {
    printf("\tfailed.\n");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    perror("\t[+] /foo");
    passed_suite += 1;
  }

  printf("[-] testing `open` regular file `/bin/fs`...");
  if (open("/bin/fs", O_RDONLY) < 0) {
    printf("\tfailed.\n");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `open` directory `/bin`...");
  if (open("/bin", O_RDONLY) < 0) {
    printf("\tfailed.\n");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `open` device file `/dev/random`...");
  int random_fd = -1;
  if ((random_fd = open("/dev/random", O_RDONLY)) < 0) {
    printf("\tfailed.\n");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `read` device file `/dev/random`...");
  char buf[32] = {0};
  size_t read_num = 0;
  if ((read_num = read(random_fd, buf, sizeof(buf))) != sizeof(buf)) {
    printf("\tfailed: %lu != %lu\n", read_num, sizeof(buf));
    perror("\t[+] Reason");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `write` to `stdout`...");
  char *msg = "Hello World!\n";
  int num = 0;
  if ((num = write(1, msg, strlen(msg))) != strlen(msg)) {
    printf("\tfailed: %d\n", num);
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `stat` a file `/bin/fs`...");
  if (test_stat("/bin/fs") < 0) {
    printf("\tfailed.\n");
    perror("\t[+] /bin/fs");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] Test summary:\n");
  printf("\t[+] Passed: %d\n\t[+] Failed: %d\n", passed_suite, failed_suite);

  return 0;
}
