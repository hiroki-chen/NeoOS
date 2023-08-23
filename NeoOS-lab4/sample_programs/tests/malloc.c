#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

static void generate_random_alphanumeric(char *buffer, int buffer_size) {
  int i;
  srand(time(NULL));  // Seed the random number generator

  // Generate random alphanumeric characters and store them in the buffer
  for (i = 0; i < buffer_size - 1; i++) {
    int r = rand() % 62;
    if (r < 10) {
      buffer[i] = '0' + r;  // Random digit between 0 and 9
    } else if (r < 36) {
      buffer[i] = 'a' + r - 10;  // Random lowercase letter between a and z
    } else {
      buffer[i] = 'A' + r - 36;  // Random uppercase letter between A and Z
    }
  }
  buffer[buffer_size - 1] =
      '\0';  // Add null terminator to the end of the buffer
}

/// Matrix addition.
static void matrix_addition(int rows, int cols) {
  int i, j;
  int **matrix1, **matrix2, **result;

  // Allocate memory for matrix1
  matrix1 = (int **)malloc(rows * sizeof(int *));
  for (i = 0; i < rows; i++) {
    matrix1[i] = (int *)malloc(cols * sizeof(int));
  }

  // Allocate memory for matrix2
  matrix2 = (int **)malloc(rows * sizeof(int *));
  for (i = 0; i < rows; i++) {
    matrix2[i] = (int *)malloc(cols * sizeof(int));
  }

  // Allocate memory for result matrix
  result = (int **)malloc(rows * sizeof(int *));
  for (i = 0; i < rows; i++) {
    result[i] = (int *)malloc(cols * sizeof(int));
  }

  // Initialize matrix1 with random values
  srand(time(NULL));
  for (i = 0; i < rows; i++) {
    for (j = 0; j < cols; j++) {
      matrix1[i][j] = rand() % 10;
    }
  }

  // Initialize matrix2 with random values
  for (i = 0; i < rows; i++) {
    for (j = 0; j < cols; j++) {
      matrix2[i][j] = rand() % 10;
    }
  }

  // Add matrices
  for (i = 0; i < rows; i++) {
    for (j = 0; j < cols; j++) {
      result[i][j] = matrix1[i][j] + matrix2[i][j];
    }
  }

  // Show mmap.
  int pid = getpid();
  char name[32] = "/proc/self/maps";
  // sprintf(name, "/proc/self/maps", pid);
  int fd = open(name, O_RDONLY);
  printf("opened %d\n", fd);
  char buf[4096] = {0};
  read(fd, buf, sizeof(buf));
  printf("the map is\n%s\n", buf);

  // Free memory for matrices
  for (i = 0; i < rows; i++) {
    free(matrix1[i]);
  }
  free(matrix1);

  for (i = 0; i < rows; i++) {
    free(matrix2[i]);
  }
  free(matrix2);

  for (i = 0; i < rows; i++) {
    free(result[i]);
  }
  free(result);
}

static void matrix_multiplication(int m, int n, int p) {
  int i, j, k;
  int **matrix1, **matrix2, **result;

  // Allocate memory for matrix1
  matrix1 = (int **)malloc(m * sizeof(int *));
  for (i = 0; i < m; i++) {
    matrix1[i] = (int *)malloc(n * sizeof(int));
  }

  // Allocate memory for matrix2
  matrix2 = (int **)malloc(n * sizeof(int *));
  for (i = 0; i < n; i++) {
    matrix2[i] = (int *)malloc(p * sizeof(int));
  }

  // Allocate memory for result matrix
  result = (int **)malloc(m * sizeof(int *));
  for (i = 0; i < m; i++) {
    result[i] = (int *)malloc(p * sizeof(int));
  }

  // Initialize matrix1 with random values
  srand(time(NULL));
  for (i = 0; i < m; i++) {
    for (j = 0; j < n; j++) {
      matrix1[i][j] = rand() % 10;
    }
  }

  // Initialize matrix2 with random values
  for (i = 0; i < n; i++) {
    for (j = 0; j < p; j++) {
      matrix2[i][j] = rand() % 10;
    }
  }

  // Multiply matrices
  for (i = 0; i < m; i++) {
    for (j = 0; j < p; j++) {
      result[i][j] = 0;
      for (k = 0; k < n; k++) {
        result[i][j] += matrix1[i][k] * matrix2[k][j];
      }
    }
  }

  // Free memory for matrices
  for (i = 0; i < m; i++) {
    free(matrix1[i]);
  }
  free(matrix1);

  for (i = 0; i < n; i++) {
    free(matrix2[i]);
  }
  free(matrix2);

  for (i = 0; i < m; i++) {
    free(result[i]);
  }
  free(result);
}

int main() {
  printf("[-] testing `malloc` a char array with 0x1000 size...");
  fflush(stdout);
  char *buf = (char *)(malloc(0x1000));
  printf("\tpassed.\n");

  printf("[-] testing `memset` a char array with 0x1000 size...");
  fflush(stdout);
  memset(buf, 0x0, 0x1000);
  printf("\tpassed.\n");

  printf("[-] testing generating random ascii bytes for this array...");
  fflush(stdout);
  generate_random_alphanumeric(buf, 0x1000);
  printf("\tpassed.\n");
  printf("\t[+] the first 0x10 characters are given as %.*s\n", 0x10, buf);

  printf("[-] testing `free` a char array with 0x1000 size...");
  fflush(stdout);
  free(buf);
  printf("\tpassed.\n");

  printf("[-] testing matrix addition...");
  fflush(stdout);
  matrix_addition(1024, 1024);
  printf("\tpassed.\n");

  printf("[-] testing matrix multiplication...");
  fflush(stdout);
  matrix_multiplication(1024, 1024, 1024);
  printf("\tpassed.\n");

  return 0;
}
