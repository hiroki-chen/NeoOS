#!/usr/bin/env python3

# Do some necessary preparations for the kernel.
import os
import pwd
import sys
import shutil
import subprocess

# If this is python2, check if python3 is available and re-execute with that
# interpreter. Only python3 allows downloading CI LLVM.
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
    subprocess.run('sudo install -y nasm'.split())

# Check if rust is installed.
path = os.environ['PATH']
cargo_path = '/home/' + pwd.getpwuid(os.getuid())[0] + '/.cargo/bin'
os.environ['PATH'] = cargo_path + ':' + path
if shutil.which('cargo') is None:
    print('Installing Rust toolchain...')
    subprocess.run(
        'curl --proto \'=http\' --tlsv1.2 -sSf https://sh.rustup.rs | sh'.split())
