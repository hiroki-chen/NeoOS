#include <dlfcn.h>

int add(int, int);
int sub(int, int);
int mul(int, int);

int main() {
  while (1) {
    add(2, 3);
  }

  return 0;
}
