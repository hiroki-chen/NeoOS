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
    printf("%s ", ent->d_name);
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
  fflush(stdout);
  if (test_getdents64("/") != 0) {
    printf("\tfailed.\n");
    perror("\t[+] test_gedents64");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf(
      "[-] testing `getdents64` for root directory `/foo` and should fail...");
  fflush(stdout);
  if (test_getdents64("/foo") == 0) {
    printf("\tfailed.\n");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    perror("\t[+] test_gedents64");
    passed_suite += 1;
  }

  printf("[-] testing `open` regular file `/bin/fs`...");
  fflush(stdout);
  int fs_fd = -1;
  if ((fs_fd = open("/bin/fs", O_RDONLY)) < 0) {
    printf("\tfailed.\n");
    perror("[+]\t open");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `open` directory `/bin`...");
  fflush(stdout);
  if (open("/bin", O_RDONLY) < 0) {
    printf("\tfailed.\n");
    perror("[+]\t open");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `open` device file `/dev/random`...");
  fflush(stdout);
  int random_fd = -1;
  if ((random_fd = open("/dev/random", O_RDONLY)) < 0) {
    printf("\tfailed.\n");
    perror("[+]\t open");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `read` device file `/dev/random`...");
  fflush(stdout);
  char buf[32] = {0};
  size_t read_num = 0;
  if ((read_num = read(random_fd, buf, sizeof(buf))) != sizeof(buf)) {
    printf("\tfailed: %lu != %lu\n", read_num, sizeof(buf));
    perror("\t[+] read");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `write` to `stdout`...");
  fflush(stdout);
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
  fflush(stdout);
  if (test_stat("/bin/fs") < 0) {
    printf("\tfailed.\n");
    perror("\t[+] test_stat");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `getcwd`...");
  fflush(stdout);
  if (getcwd(buf, sizeof(buf)) < 0) {
    printf("\tfailed.\n");
    perror("\t[+] getcwd");
    failed_suite += 1;
  } else {
    printf("\tpassed: %s\n", buf);
    passed_suite += 1;
  }

  printf("[-] testing `dup` the file descriptor of `/bin/fs`...");
  fflush(stdout);
  int target_fd = 0x123;
  if (dup2(fs_fd, target_fd) < 0) {
    printf("\tfailed.\n");
    perror("\t[+] dup2");
    failed_suite += 1;
  } else {
    printf("\tpassed: %s\n", buf);
    passed_suite += 1;
  }

  printf("[-] testing `read` the duplicated file descriptor of `/bin/fs`...");
  if (read(target_fd, buf, sizeof(buf)) != sizeof(buf)) {
    printf("\tfailed.\n");
    perror("\t[+] read");
    failed_suite += 1;
  } else {
    printf("\tpassed,\n");
    passed_suite += 1;
  }

  printf("[-] testing `open` special file `/proc/self/maps`...");
  fflush(stdout);
  int maps_fd = -1;
  if ((maps_fd = open("/proc/self/maps", O_RDONLY)) < 0) {
    printf("\tfailed.\n");
    perror("[+]\t open");
    failed_suite += 1;
  } else {
    printf("\tpassed.\n");
    passed_suite += 1;
  }

  printf("[-] testing `read` special file `/proc/self/maps`...");
  fflush(stdout);
  char maps[4096] = {0};
  if (read(maps_fd, maps, sizeof(maps)) < 0) {
    printf("\tfailed.\n");
    perror("[+]\t read");
    failed_suite += 1;
  } else {
    printf("\tpassed:\n%s\n", maps);
    passed_suite += 1;
  }

  printf("[-] Test summary:\n");
  printf("\t[+] Passed: %d\n\t[+] Failed: %d\n", passed_suite, failed_suite);

  return 0;
}
