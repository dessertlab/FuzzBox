#!/bin/bash

sudo chmod 0777 /dev/shm
# find /dev/shm -type f -name '*sem*' -exec rm {} \; 
sudo rm -r /dev/shm/*
sleep 1

cd fuzzbox_patch/plugins/
make customplugin
cd ../../usr
./script_MILS.sh $1
