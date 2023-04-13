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

.phony: all clean clean_app test efi debug clippy sample_program

UNAME		:= $(shell uname)
BACKTRACE	?= 5
OS_LOG_LEVEL	?= info
TEST_KERNEL	?= ./test_jump.S
FILE_SYSTEM 	?= apfs
MONITOR		?= 0
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
DISKUTIL_GET	?= diskutil list | grep /dev | tail -1 | awk '{print $$1}'

ifeq ($(UNAME), Darwin)
	UEFI := $(shell brew list qemu | grep edk2-x86_64-code.fd)
	BUILD_COMMAND := cargo build
else
	UEFI := /usr/share/OVMF/OVMF_CODE.fd
	BUILD_COMMAND := cargo build --features=x2apic,linux_gateway
endif

# Need to add `sudo` to make sure QEMU can access /dev/net/tun: but why changing permission and user group
# won't take any effect? Strange.
QEMU_COMMAND	?= sudo qemu-system-x86_64 \
			-drive if=pflash,format=raw,readonly=on,file=$(UEFI) \
			-drive format=raw,file=fat:rw:esp \
			-nographic -smp cores=4 -no-reboot -m 8G -rtc clock=vm,base=localtime \
			-drive format=qcow2,file=$(DISK),media=disk,cache=writeback,id=sfsimg,if=none \
			-device ahci,id=ahci0 \
			-device ide-hd,drive=sfsimg,bus=ahci0.0 \
			-cpu host

ifeq ($(MONITOR), 1)
	QEMU_COMMAND += -monitor telnet:127.0.0.1:23333,server,nowait
endif

ifeq ($(UNAME), Darwin)
	QEMU_COMMAND += -accel hvf -machine type=q35 \
			-nic vmnet-host,mac=52:54:0:12:34:57,model=e1000e
else
	QEMU_COMMAND += -enable-kvm \
			-netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
			-device e1000e,netdev=net0
endif

ifeq ($(DEBUG), 1)
	QEMU_COMMAND += -s -S
endif

all: kernel

sample_program:
	@mkdir -p $(WORK_DIR)/bin
	@mkdir -p $(WORK_DIR)/lib
ifeq ($(UNAME), Linux)
	@cp /usr/lib/x86_64-linux-musl/libc.so $(WORK_DIR)/lib/ld-musl-x86_64.so.1
endif
	@$(MAKE) -C sample_programs

# Creates virtual hard disk.
hard_disk: sample_program
	@echo 'Building the hard disk with a given filesystem... This may take a while.'
ifeq ($(FILE_SYSTEM), sfs)
	@cd $(WORK_DIR) && mkdir -p fs && echo 'test data' >> fs/foo
	@cd $(WORK_DIR) && rcore-fs-fuse $(DISK) fs zip
	@cd $(WORK_DIR) && qemu-img convert -f raw $(DISK) -O qcow2 $(DISK).qcow2
	@cd $(WORK_DIR) && qemu-img resize $(DISK).qcow2 +1G && mv $(DISK).qcow2 $(DISK)
else
	@cd $(WORK_DIR) && dd if=/dev/zero bs=1M count=400 > $(DISK)

ifeq ($(UNAME), Darwin)
	@cd $(WORK_DIR) && \
		hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount $(DISK) | \
		xargs -I {} newfs_apfs -v "untitled" {}
	@$(DISKUTIL_GET) | xargs -I {} diskutil mountDisk {}

	@cd /Volumes/untitled && mkdir dev proc
	@cd $(WORK_DIR) && cp -r bin /Volumes/untitled && cp -r lib /Volumes/untitled && cp busybox /Volumes/untitled
	@$(DISKUTIL_GET) | xargs -I {} hdiutil detach {}
else
	@cd $(WORK_DIR) && mkfs.apfs $(DISK)
	@cd $(WORK_DIR) && sudo mount -o loop,readwrite $(DISK) /mnt
	@cd /mnt && mkdir dev proc usr etc
	@mkdir -p /mnt/usr/local/nginx/conf
	@cd $(WORK_DIR) && cp nginx.conf /mnt/usr/local/nginx/conf
	@mkdir -p /mnt/usr/local/nginx/logs && touch /mnt/usr/local/nginx/logs/error.log
	@echo 'nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin' >> /mnt/etc/passwd
	@echo 'root:x:0:0:root:/root:./busybox' >> /mnt/etc/passwd
	@echo 'nogroup:x:65534:' >> /mnt/etc/group
	@cd $(WORK_DIR) && cp -r bin /mnt && cp -r lib /mnt && cp busybox /mnt
	@sudo umount /mnt
endif
	@cd $(WORK_DIR) && cp $(DISK) $(DISK).backup
	@cd $(WORK_DIR) && qemu-img convert -f raw $(DISK) -O qcow2 $(DISK).qcow2
	@cd $(WORK_DIR) && qemu-img resize $(DISK).qcow2 +1G && mv $(DISK).qcow2 $(DISK)
endif


debug: kernel
	@$(QEMU_COMMAND) -s S &
	@sleep 1
	@sudo gdb $(KERNEL_TARGET)

kernel: efi
	@cd kernel && RUSTFLAGS=-g RUST_BACKTRACE=$(BACKTRACE) OS_LOG_LEVEL=$(OS_LOG_LEVEL) \
			$(BUILD_COMMAND)
	@cp $(KERNEL_TARGET) $(KERNEL_IMAGE)

efi:
	@mkdir -p $(BOOT_DIR)
	@cd boot && cargo build
	@cp $(EFI_TARGET) $(EFI)

run: kernel hard_disk
	@cp boot.cfg $(BOOT_DIR)
	@cd $(WORK_DIR) && $(QEMU_COMMAND)

clean:
	@cargo clean
	@rm -rf $(WORK_DIR)

$(TEST_IMAGE): $(TEST_KERNEL)
	@gcc $^ -o $@ -no-pie -nostartfiles

test_run: efi $(TEST_IMAGE) hard_disk
	@cp boot.cfg $(BOOT_DIR)
	@cd $(WORK_DIR) && $(QEMU_COMMAND)

clippy:
	@cargo clippy

clean_app:
	@$(MAKE) -C sample_programs clean
