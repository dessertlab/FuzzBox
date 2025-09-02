#!/bin/bash

cd ..
cd qemu
cd build 
clear
 ../configure --target-list="aarch64-softmmu arm-softmmu ppc64-softmmu ppc-softmmu" --disable-xen --enable-plugins 
sudo make -j8
sudo make install
cd ..
cd ..
sudo bash ./usr/start_mils.sh $1

# the input parameter should be the folder where the target binary is placed: e.g. "JSONPARSER/json_easy"
