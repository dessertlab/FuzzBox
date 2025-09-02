repo_directory="path_to_the_cloned_repo"
disk_directory="$repo_directory/target_bin/MILS"
target_directory="$repo_directory/target_bin/MILS/$1/obj_wrSbc85xx"
target_binary="$target_directory/milsSystem.elf"
home_directory="$repo_directory/usr"

# Functions to track
crash_track_name="schedSuspendVb"
msg_track_name="sendMessageSIPC"
save_snap_track_name="dummy_fun"
load_snap_track_name="sipcMessageReceive"

# CPUState struct offsets
ppc_offset1="33552"
ppc_offset2="4528"
#ppc_registers=(3 4)  # registers where function parameters are passed (these numbers are embedded into TCG plugin for MILS experiment)

# QEMU binaries
qemu_ppc="/usr/local/bin/qemu-system-ppc"	# PPC 32 bit
qemu_ppc_64="/usr/local/bin/qemu-system-ppc64"	# PPC 64 bit

# TCG Plugin
plugin_bin="$repo_directory/fuzzbox_patch/plugins/customplugin.so"
plugin_output="./pluginlog.txt"
mode=FUZZING_MODE

cd $target_directory
crash_track_address=$(nm hypervisor | grep $crash_track_name | cut -d ' ' -f1) 
msg_track_address=$(nm vb_hae2_base.elf | grep $msg_track_name | cut -d ' ' -f1)
save_snap_track_address=$(nm hypervisor | grep $save_snap_track_name | cut -d ' ' -f1) 
load_snap_track_address=$(nm sample_vb.sm | grep $load_snap_track_name -m 1| cut -d ' ' -f1)
	
CONFIG_TYPE="SMTP_NOCOMM"
if [ "$CONFIG_TYPE" == "TINYEXPR_NOCOMM" ]; then
	msg_track_address=000112dc # go123
	msg_track_address=$(nm sample_vb.sm | grep "go123" | cut -d ' ' -f1) 
	crash_track_address=13e40 # 13e40
elif [ "$CONFIG_TYPE" == "TINYEXPR_COMM" ]; then
	crash_track_address=$(nm hypervisor | grep $crash_track_name | cut -d ' ' -f1) 
	msg_track_address=$(nm vb_hae2_base.elf | grep $msg_track_name | cut -d ' ' -f1)
elif [ "$CONFIG_TYPE" == "SMTP" -o "$CONFIG_TYPE" == "JSON_PARSER_COMM" ]; then
    crash_track_address=$(nm hypervisor | grep "$crash_track_name" | cut -d ' ' -f1)
    msg_track_address=$(nm vb_hae2_base.elf | grep "$msg_track_name" | cut -d ' ' -f1)
elif [ "$CONFIG_TYPE" == "SMTP_NOCOMM" ]; then
    crash_track_address=$(nm hypervisor | grep "$crash_track_name" | cut -d ' ' -f1)
    msg_track_address=$(nm sample_vb.sm | grep "raw_to_fuzz" | cut -d ' ' -f1)
elif [ "$CONFIG_TYPE" == "JPEG_NOCOMM" ]; then
	crash_track_address=$(nm hypervisor | grep "$crash_track_name" | cut -d ' ' -f1)
	msg_track_address=$(nm sample_vb.sm | grep "read_JPEG_stream" | cut -d ' ' -f1)
elif [ "$CONFIG_TYPE" == "JSON_PARSER_NOCOMM" ]; then
	crash_track_address=$(nm hypervisor | grep "$crash_track_name" | cut -d ' ' -f1)
	msg_track_address=$(nm sample_vb.sm | grep "start_jsonparser_fromarray" | cut -d ' ' -f1)
elif [ "$CONFIG_TYPE" == "SEMPLICE" ]; then
	crash_track_address=$(nm hypervisor | grep "$crash_track_name" | cut -d ' ' -f1)
	msg_track_address=$(nm sample_vb.sm | grep "semplice" | cut -d ' ' -f1)
elif [ "$CONFIG_TYPE" == "SMTP_SNAPSHOTv3" ]; then
	crash_track_address=$(nm hypervisor | grep "$crash_track_name" | cut -d ' ' -f1)
	msg_track_address=$(nm sample_vb.sm | grep "receiveMessageSIPCSnapshot" | cut -d ' ' -f1)
	save_snap_track_address=$(nm vb_hae2_base.elf | grep "sendMessageSIPC" | cut -d ' ' -f1)
elif [ "$CONFIG_TYPE" == "SMTP_SNAPSHOTv7" ]; then
	crash_track_address=$(nm hypervisor | grep "$crash_track_name" | cut -d ' ' -f1)
	msg_track_address=$(nm vb_hae2_base.elf | grep "sendMessageSIPC" | cut -d ' ' -f1)
	save_snap_track_address=$(nm vb_hae2_base.elf | grep "dummy_fun" | cut -d ' ' -f1)
	load_snap_track_address=$(nm sample_vb.sm | grep "sipcMessageReceive" -m 1| cut -d ' ' -f1)
fi


export QEMU_LOG="nochain"

# Execute QEMU-fuzz
cd $home_directory
pwd
$qemu_ppc -M wrsbc8548_vxworks -drive file=$disk_directory/disk.qcow2 -cpu MPC8548E_v20 -m 1G  \
	-serial file:serial1.txt -serial file:serial2.txt -kernel $target_binary -d nochain \
	-plugin  $plugin_bin,fuzzer_mode=$mode,crash_track=$crash_track_address,msg_track=$msg_track_address,offset1=$ppc_offset1,offset2=$ppc_offset2,save_snap_track=$save_snap_track_address,load_snap_track=$load_snap_track_address, \
	-d plugin -D $plugin_output -name MILS_FUZZING,process="qemu"
