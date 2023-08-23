.phony: all clean

all:
	@$(MAKE) -C ./simple_c
	@$(MAKE) -C ./simple_tcp
	@$(MAKE) -C ./rust
	@$(MAKE) -C ./nginx
	@$(MAKE) -C ./tests
	@$(MAKE) -C ./busybox-musl

clean:
	@$(MAKE) -C ./simple_c clean
	@$(MAKE) -C ./simple_tcp clean
	@$(MAKE) -C ./rust clean
	@$(MAKE) -C ./nginx clean
