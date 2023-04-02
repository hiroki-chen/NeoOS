include ../common.mk

CARGO_DEBUG	?= 1

ifeq ($(CARGO_DEBUG), 1)
	CARGO_OUTPUT = $(CURDIR)/target/x86_64-unknown-neoos-musl/debug
else
	CARGO_COMMAND += --release
	CARGO_OUTPUT = $(CURDIR)/target/x86_64-unknown-neoos-musl/release
endif

.phony: hello all clean

hello:
	cargo build $(CARGO_COMMAND) --bin hello_rust
	@cp "$(CARGO_OUTPUT)/hello_rust" $(OUTPUT_PATH)

clean:
	@cargo clean
