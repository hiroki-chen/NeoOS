# Defines how we handle any traps into the kernel.

.text
.global __handle_trap

__handle_trap:
  # This function temporarily does nothing.
  hlt
