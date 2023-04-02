include ../common.mk

CARGO_OUTPUT_DIR	:= $(CURDIR)/target/x86_64-unknown-neoos-musl/release
CARGO_BINARY		:= $(CARGO_OUTPUT_DIR)/rust

.phony: all clean

all:
	@cargo build --release
	@cp $(CARGO_BINARY) $(OUTPUT_PATH)

clean:
	@cargo clean
