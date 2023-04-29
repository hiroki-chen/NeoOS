#!/usr/bin/env python3

# Do some necessary preparations for the kernel.
import os
import pwd
import sys
import shutil
import subprocess

# If this is python2, check if python3 is available and re-execute with that interpreter.
#
# This matters if someone's system `python` is python2.
if sys.version_info.major < 3:
    try:
        os.execvp("py", ["py", "-3"] + sys.argv)
    except OSError:
        try:
            os.execvp("python3", ["python3"] + sys.argv)
        except OSError:
            # Python 3 isn't available, fall back to python 2
            pass

# Check if nasm is installed.
if shutil.which('nasm') is None:
    print('Installing `nasm`...')
    subprocess.run('sudo apt install -y nasm'.split())

# Check if QEMU is installed.
if shutil.which('qemu-system-x86_64') is None:
    print('Installing `qemu`, `OVMF` and KVM environment.')
    subprocess.run(
        'sudo apt install -y qemu-system ovmf qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils'.split())
    subprocess.run('sudo adduser `id -un` kvm'.split())

# Check if rust is installed.
path = os.environ['PATH']
cargo_path = '/home/' + pwd.getpwuid(os.getuid())[0] + '/.cargo/bin'
os.environ['PATH'] = cargo_path + ':' + path
if shutil.which('cargo') is None:
    print('Installing Rust toolchain...')
    subprocess.run(
        'curl --proto \'=http\' --tlsv1.2 -sSf https://sh.rustup.rs | sh'.split())
    subprocess.run('cargo -V'.split())

# Add rust-src. This should fix the case if the user has already installed cargo.
f = open('./rust-toolchain')
toolchain_version = f.read().strip('\n')
subprocess.run('rustup override set {}-x86_64-unknown-linux-gnu'.format(toolchain_version).split())
subprocess.run(
    'rustup component add rust-src llvm-tools-preview --toolchain {}-x86_64-unknown-linux-gnu'.format(toolchain_version).split())
subprocess.run('cargo install cargo-binutils'.split())

if shutil.which('rcore-fs-fuse') is None:
    # For creating the SFS image.
    subprocess.run(
        'cargo install --git https://github.com/rcore-os/rcore-fs.git --rev 7f5eeac --force rcore-fs-fuse'.split()
    )

# Install musl.
if shutil.which('musl-gcc') is None:
    print('installing musl toolchain...')
    subprocess.run('sudo apt install -y musl musl-tools'.split())

print('Done!')
