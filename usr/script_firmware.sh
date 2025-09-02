#!/bin/bash

#path and variables
repo_dir="path_to_the_cloned_repository"
target_dir="$repo_dir/target_bin/armhf"
home_dir="$repo_dir/usr"

kernel="$target_dir/vmlinuz-3.2.0-4-vexpress"
initrd="$target_dir/initrd.img-3.2.0-4-vexpress"
drive="$target_dir/debian_wheezy_armhf_standard.qcow2"

target_dir_mips="$repo_dir/target_bin/mips/CVE-2019-11399"
kernel_mips="$target_dir_mips/vmlinux-3.2.0-4-4kc-malta"
drive_mips="$target_dir_mips/debian_wheezy_mips_standard.qcow2"

home_directory="$repo_dir/usr"

# CPUState struct offsets
arm_offset1="33552"
arm_offset2="6768" # "6896"
arm_registers=(3 4)
mips_offset1="33672"
mips_offset2="1840"

# QEMU binaries
qemu_arm="/usr/local/bin/qemu-system-arm"	# ARM 32 bit
qemu_arm_64="/usr/local/bin/qemu-system-aarch64"	# ARM 64 bit
qemu_mips="/usr/local/bin/qemu-system-mips"
qemu_mips_64="/usr/local/bin/qemu-system-mips64"

# TCG Plugin
linux_plugin_bin="$repo_dir/fuzzbox_patch/plugins/customplugin.so"
plugin_output="plugin_log.txt"
mode=FUZZING_MODE
crash_track_address=0x800e617c #do_coredump!
msg_track_address=0x80201f04 #sys_recvfrom
crash_track_address_mips=0x8020c8e8 #do_coredump
msg_track_address_mips=0x80497b94 #sys_recvfrom

# Client Plugin
client_plugin_bin="$repo_dir/fuzzbox_patch/plugins/clientplugin.so"
request_protocol="http"
requests_filename="$repo_dir/fuzzbox_patch/plugins/requests.json"

# Other functions to intercept
# 80201f04 = recvfrom
# 80201e14 = sendto
# 80202930 # __sk_mem_reclaim 


#sudo ssh start
sudo systemctl start ssh
sudo tunctl -t tap0
sudo ifconfig tap0 192.168.2.1/24
pwd
(cd ./python_server && python3 -m http.server 8000 & cd ..)

local_port=80
local_ip=10.0.2.15
remote_port=80
remote_ip=192.168.2.2

#tmux new-session -d -s "local"

# Send the loop command to the "local" tmux session
#tmux send-keys -t "local" "for i in {1..10}; do ssh -L ${local_ip}:${local_port}:${remote_ip}:${remote_port} root@${local_ip} -o ConnectTimeout=10 -o StrictHostKeyChecking=no; echo \$i; echo 'restart'; sleep 10s; done" C-m

tmux new -s "local" -d "for i in {1..10} ;do ssh -L ${local_ip}:${local_port}:${remote_ip}:${remote_port} root@${local_ip} -o ConnectTimeout=10 -o StrictHostKeyChecking=no; echo $i; echo 'restart'; sleep 10s ;done"


# Execute QEMU-fuzz
cd $home_directory
#$qemu_arm -M vexpress-a9 -cpu cortex-a9  -kernel $kernel -initrd $initrd -drive if=sd,file=$drive -append "root=/dev/mmcblk0p2" -net nic -net tap,ifname=tap0,script=no,downscript=no, -plugin $linux_plugin_bin,fuzzer_mode=FUZZING_MODE,crash_track=$crash_track_address,msg_track=$msg_track_address,offset1=$arm_offset1,offset2=$arm_offset2, -d plugin -D $plugin_output -name QEMU_FUZZ,process="qemu"

$qemu_mips -m 4G -M malta -kernel $kernel_mips -hda $drive_mips -append "root=/dev/sda1" -net nic -net tap,ifname=tap0,script=no,downscript=no, -plugin $linux_plugin_bin,fuzzer_mode=FUZZING_MODE,crash_track=$crash_track_address_mips,msg_track=$msg_track_address_mips,offset1=$mips_offset1,offset2=$mips_offset2, -name QEMU_FUZZ,process="qemu"
