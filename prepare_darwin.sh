#!/bin/bash

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  echo "Do not run this script on Linux."
  exit 1
fi

echo "[-] Preparing packages"

brew install nasm qemu

echo "[-] Preparing packages OK"

echo "[-] Preparing musl-gcc"

brew install filosottile/musl-cross/musl-cross
wget https://musl.cc/x86_64-linux-musl-cross.tgz -O ../x86_64-linux-musl-cross.tgz
tar -xf ../x86_64-linux-musl-cross.tgz -C ..
sudo mkdir -p /usr/local/lib/x86_64-linux-musl
sudo mkdir -p /usr/local/include/x86_64-linux-musl
echo -e "\t[+] Copying to the target directory"
sudo cp -r ../x86_64-linux-musl-cross/x86_64-linux-musl/include /usr/local/include/x86_64-linux-musl
sudo cp -r ../x86_64-linux-musl-cross/x86_64-linux-musl/lib /usr/local/lib/x86_64-linux-musl

echo "[-] Preparing musl-gcc OK"
