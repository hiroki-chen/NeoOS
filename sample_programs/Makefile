UNAME		:= $(shell uname)

.phony: all clean

all:
	@$(MAKE) -C ./simple_c
	@$(MAKE) -C ./simple_tcp
	@$(MAKE) -C ./rust
# Nginx-musl cannot be built on macOS.
ifeq ($(UNAME), Linux)
# @$(MAKE) -C ./nginx
endif
	@$(MAKE) -C ./tests
	@$(MAKE) -C ./busybox-musl

clean:
	@$(MAKE) -C ./simple_c clean
	@$(MAKE) -C ./simple_tcp clean
	@$(MAKE) -C ./rust clean
	@$(MAKE) -C ./nginx clean
