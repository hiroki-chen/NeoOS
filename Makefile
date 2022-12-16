# Copyright (c) 2022 Haobin Chen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

.phony: all clean test efi debug clippy

BACKTRACE			?= 5
OS_LOG_LEVEL	?= info
TEST_KERNEL		?= ./test_jump.S
WORK_DIR 			?= ./test
BOOT_DIR 			:= $(WORK_DIR)/esp/efi/boot
EFI_TARGET		?= target/x86_64-unknown-uefi/debug/boot.efi
EFI 		 			?= $(BOOT_DIR)/bootx64.efi
KERNEL_TARGET	?= target/x86_64/debug/kernel
KERNEL_IMAGE	?= $(BOOT_DIR)/kernel.img
DEBUG					?= 1
DISK					?= disk.img
DISK_SIZE			?= 10G
QEMU_COMMAND	?= qemu-system-x86_64 -enable-kvm \
									-drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
									-drive if=pflash,format=raw,readonly=on,file=OVMF_VARS.fd \
									-drive format=raw,file=fat:rw:esp \
									-nographic -smp 2 -no-reboot -m 4G -rtc clock=vm \
									-drive format=qcow2,file=$(DISK),media=disk,cache=writeback,id=sfsimg,if=none \
									-device ahci,id=ahci0 \
									-device ide-hd,drive=sfsimg,bus=ahci0.0

ifeq ($(DEBUG), 1)
	QEMU_COMMAND += -s -S
endif

all: kernel

# Creates virtual hard disk
hard_disk:
	@cd $(WORK_DIR) && qemu-img create -f qcow2 $(DISK) $(DISK_SIZE)

debug: kernel
	@$(QEMU_COMMAND) -s S &
	@sleep 1
	@sudo gdb $(KERNEL_TARGET)

kernel: efi
	@cd kernel && RUSTFLAGS=-g RUST_BACKTRACE=$(BACKTRACE) OS_LOG_LEVEL=$(OS_LOG_LEVEL) \
								cargo build -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem \
								--target ./x86_64.json
	@cp $(KERNEL_TARGET) $(KERNEL_IMAGE)

efi:
	@mkdir -p $(BOOT_DIR)
	@cd boot && cargo build -Zbuild-std=core,alloc -Zbuild-std-features=compiler-builtins-mem --target x86_64-unknown-uefi
	@cp $(EFI_TARGET) $(EFI)

run: kernel hard_disk
	@cp boot.cfg $(BOOT_DIR)
	@cd $(WORK_DIR) && cp /usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_VARS.fd .
	@cd $(WORK_DIR) && \
			$(QEMU_COMMAND)

clean:
	@cargo clean
	@rm -r $(WORK_DIR)

test: $(TEST_KERNEL)
	@gcc $^ -o test.img -no-pie -nostartfiles
	@mv test.img $(BOOT_DIR)

clippy:
	@cargo clippy
