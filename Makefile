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

BACKTRACE	?= 5
OS_LOG_LEVEL	?= info
TEST_KERNEL	?= ./test_jump.S
FILE_SYSTEM ?= sfs
WORK_DIR 	?= ./test
BOOT_DIR 	:= $(WORK_DIR)/esp/efi/boot
EFI_TARGET	?= target/x86_64-unknown-uefi/debug/boot.efi
EFI 		?= $(BOOT_DIR)/bootx64.efi
KERNEL_TARGET	?= target/x86_64/debug/kernel
KERNEL_IMAGE	?= $(BOOT_DIR)/kernel.img
TEST_IMAGE	?= $(KERNEL_IMAGE)
DEBUG		?= 0
DISK		?= disk.img
DISK_SIZE	?= 10G
QEMU_COMMAND	?= qemu-system-x86_64 -enable-kvm \
			-drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd \
			-drive if=pflash,format=raw,readonly=on,file=OVMF_VARS.fd \
			-drive format=raw,file=fat:rw:esp \
			-nographic -smp cores=4 -no-reboot -m 4G -rtc clock=vm \
			-drive format=qcow2,file=$(DISK),media=disk,cache=writeback,id=sfsimg,if=none \
			-device ahci,id=ahci0 \
			-device ide-hd,drive=sfsimg,bus=ahci0.0 \
			-cpu host

ifeq ($(DEBUG), 1)
	QEMU_COMMAND += -s -S
endif

all: kernel

# Creates virtual hard disk.
hard_disk:
	@echo 'Building the hard disk with a given filesystem... This may take a while.'
ifeq ($(FILE_SYSTEM), sfs)
	@cd $(WORK_DIR) && mkdir -p fs && echo 'test data' >> fs/foo
	@cd $(WORK_DIR) && rcore-fs-fuse $(DISK) fs zip
	@cd $(WORK_DIR) && qemu-img convert -f raw $(DISK) -O qcow2 $(DISK).qcow2
	@cd $(WORK_DIR) && qemu-img resize $(DISK).qcow2 +1G && mv $(DISK).qcow2 $(DISK)
else
	@cd $(WORK_DIR) && dd if=/dev/zero bs=1M count=400 > $(DISK) && mkfs.apfs $(DISK)
	@cd $(WORK_DIR) && sudo mount -o loop,readwrite $(DISK) /mnt
# TODO: Add meaningful files/directories.
	@mkdir -p /mnt/foo && touch /mnt/bar && mkdir -p baz
	@sudo umount /mnt
	@cd $(WORK_DIR) && qemu-img convert -f raw $(DISK) -O qcow2 $(DISK).qcow2
	@cd $(WORK_DIR) && qemu-img resize $(DISK).qcow2 +1G && mv $(DISK).qcow2 $(DISK)
endif


debug: kernel
	@$(QEMU_COMMAND) -s S &
	@sleep 1
	@sudo gdb $(KERNEL_TARGET)

kernel: efi
	@cd kernel && RUSTFLAGS=-g RUST_BACKTRACE=$(BACKTRACE) OS_LOG_LEVEL=$(OS_LOG_LEVEL) \
			cargo build
	@cp $(KERNEL_TARGET) $(KERNEL_IMAGE)

efi:
	@mkdir -p $(BOOT_DIR)
	@cd boot && cargo build
	@cp $(EFI_TARGET) $(EFI)

run: kernel hard_disk
	@cp boot.cfg $(BOOT_DIR)
	@cd $(WORK_DIR) && cp /usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_VARS.fd .
	@cd $(WORK_DIR) && $(QEMU_COMMAND)

clean:
	@cargo clean
	@rm -r $(WORK_DIR)

$(TEST_IMAGE): $(TEST_KERNEL)
	gcc $^ -o $@ -no-pie -nostartfiles

test_run: efi $(TEST_IMAGE) hard_disk
	@cp boot.cfg $(BOOT_DIR)
	@cd $(WORK_DIR) && cp /usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_VARS.fd .
	@cd $(WORK_DIR) && $(QEMU_COMMAND)

clippy:
	@cargo clippy
