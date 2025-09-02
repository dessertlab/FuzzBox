# FuzzBox
Full-system fuzzing for binary-only embedded targets via QEMU emulation.

This repository contains the artifact associated with paper "FuzzBox: Blending Fuzzing into Emulation for Binary-Only Industrial Targets

- **FuzzBox Tool**: Provided both as a patch file for QEMU and a pre-patched QEMU version.
- **Fuzzing Scripts**: Scripts to run fuzzing on MILS-based applications and IoT Linux-based firmware.

**Note**: Due to non-disclosure constraints, we cannot publicly release the MILS-based targets of evaluation presented in the paper, which run on a closed-source hypervisor (i.e., WindRiver VxWorks MILS). However, we have included all necessary requirements for executing a fuzzing campaign on an open-source ARM-based IoT firmware, allowing you to execute the tool and evaluate the overall artifact.


## Repository Structure

The diagram below provides the organization of the repository:

````
|-- fuzzbox_patch
|-- qemu
|-- target_bin
|	-- armhf
|-- usr
|	-- coverage
|	-- pc_filtering
|	-- python_server
|	-- seeds
|-- externalclient
|-- results
|	-- iot_firmware
|	-- mils_gateway
````

1. `fuzzbox_patch` directory contains the FuzzBox patch to be applied to QEMU from scratch and a README for instructions.
2. `qemu` directory contains a pre-patched version of QEMU ready to use.
3. `target_bin` directory contains all the files related to IoT Firmware target to fuzz.
4. `usr` directory contains scripts and user programs to run the experiments.
5. `externalclient` directory contains scripts and user programs to run the IoT baseline experiments.
6. `results` directory contains raw data about experimental results and scripts to print graph and figures reported in the paper.

In the following we provide a step-by-step tutorial to set up and configure an IoT firmware for fuzzing with FuzzBox.

## System requirements and software dependencies

The testbed can be installed on a physical or virtual machine:
You need to install the following requirements:

````bash
apt-get install ninja-build;
apt-get install pkg-config;
apt-get install libglib2.0-dev;
apt-get install libpixman-1-dev; 
apt-get install libfdt-dev;
apt-get install tigervnc-viewer;
apt-get install uml-utilities
apt-get install tmux
apt-get install openssh-server
apt-get install net-tools
apt-get install libcurl4-openssl-dev
apt-get install uml-utilities;
apt-get install qemu-system;
apt-get install tmux;
apt-get install openssh-server;
apt-get install net-tools;
apt-get install python3-pip;
apt-get install python3-tk;
apt-get install python3-dev;
pip3 install keyboard;
pip3 install pyautogui;
````

Install meson if not already installed:
````bash
wget https://github.com/mesonbuild/meson/archive/0.59.3.tar.gz;
tar -xzvf 0.59.3.tar.gz;
cd meson-0.59.3;
python3 setup.py build;
python3 setup.py install;
apt-get install meson;
````

## Build and Launch Firmware
Run the build_n_go_firmware.sh script (run with -h option first to see all options). 
This script will build the patched QEMU, the necessary TCG plugin, and then automatically run the firmware with FuzzBox:
````bash
$ cd /FuzzBox/usr
$ sudo bash build_n_go_firmware.sh -d <target_dir> [mode]
````

**Note:** change properly the `repo_dir` variable in the `script_firmware.sh` script.

## Configure the Firmware
Once the firmware is running, you'll need to configure it. Follow these steps:

Connect to the firmware using VNC viewer:
````bash
$ vncviewer :5900
````
Wait for the firmware to boot up, then launch the autoconfigure.sh script from the host. Make sure to focus with the pointer on the VNC viewer interface:
````bash
$ sudo ./autoconfigure.sh <python_file>
````
The script will automatically configure the firmware and its network interface. 
If for any reason the script doesn't work, you can manually execute the commands contained in the conf_firmware.py script within the firmware VM.


**Note:** change properly the `repo_dir` variable in the `start_firmware.sh` script.

## Fuzzing Modes
### Fuzz-All
This is the simplest fuzzing mode. The plugin simply overwrites the content in memory with the fuzzer's input, "blindly." The seed must reflect the entire content of the memory; otherwise, the plugin might write only a few bytes to memory that are not meaningful for the web application being tested. The system receives various packets, both from the outside and the inside, but if you want to test a specific endpoint of the system, you need to identify the packet specifying a regex pattern. For simplicity, it is possible to provide the exact string to be recognized in memory as a pattern. The pattern must correspond to data that the tester expects, either based on the analyses conducted or (more likely) on the packet sent to the server via a specific client.

### Regex
This mode is similar to the previous one in that it also combines a terminal option with a regex pattern to identify the packet. Additionally, it allows specifying which part of the packet to fuzz by enclosing it in curly braces. The pattern consists of a prefix, the part to fuzz, and a suffix. The plugin divides the pattern into these three parts by recognizing the curly braces and then reassembles it without the braces. It identifies the "clean" pattern within the buffer to locate the packet. From the byte where the string recognized by the pattern begins, only the prefix is identified. From the point where the prefix ends, the pattern related to the section to be fuzzed is recognized. In memory, the entire content before the fuzzing section is rewritten, then the fuzzer's input is injected (which can dynamically be larger or smaller than the identified string), and finally, the rest of the memory content is rewritten.

This option provides a good balance between ease of use and control over memory writing. It is possible to enclose the entire pattern in curly braces if you want to fuzz the entire pattern.

### JSON
The option is followed by a JSON file that the plugin parses at startup and prints the values from it. In this file, you can specify multiple parameters to identify the packet and a series of parameters useful for reconstructing the packet in memory, with the ability to fuzz more than one field at a time.

If you want to fuzz an entire body parameter, including its name, you can leave the key as an empty string and define the rest in the value of that field.

## Start Fuzzing
To start the fuzzing process, send an HTTP request to the firmware using curl or a similar tool. For example, you can use the provided HTTP_client.sh script:
````bash
$ ./HTTP_client.sh
````
This will initiate the fuzzing process, sending HTTP requests to the firmware for testing.
The stats.csv file will contain the statistics of the test just conducted, including the iterations, the time taken, and the fuzzing inputs tested.

## External Mode
This mode works on all firmwares but it's intended to use on the one located in target_bin/firmadyne/asus. 
Open terminal in the asus folder and execute the following commands:
````bash
$ make 
$ ./ext_fuzzer
````
Make sure the hardcoded paths in the following files are changed accordingly: fuzzsend.c, watcher.py.
The watcher.py script currently looks in the socat output file for the sentence "Kernel Panic" to detect a crash.
