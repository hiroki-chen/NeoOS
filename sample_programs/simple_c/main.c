int main(int argc, const char** argv) {
  char buf[12] = "Hello World!";
  /* Syscall test. */
  asm("movq $1, %%rax\n"    /* sys_write       */
      "movq $1, %%rdi\n"    /* unsigned int fd */
      "movq %0, %%rsi\n"    /* const char* buf */
      "movq $12, %%rdx\n"   /* size_t len      */
      "syscall"
      :
      : "r"(buf)
      : "rax"); // "rax" is clobbered.
  /* A dead loop. */
  while (1) {
    ;
  }
}
