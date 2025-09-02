# FuzzBox internals
All the components of FuzzBox are split between a QEMU patch and a TCG plugin.

**Profiler component**. It is implemented within the file `plugins/plugin_linux_32.c` (and `/plugin_mils.c` for the MILS variant). It is responsible for intercepting configured events, such as the invocation of a target function or the occurrence of a crash. It is implemented as a callback within a TCG plugin, triggered by the configured events.

**Injector component**. It is implemented within the file `plugins/plugin_linux_32.c` as a second callback triggered sequentially after the target function invocation profiling.

**Coverage collector**. It is implemented within the file `/accel/tcg/afl-qemu-cpu-inl.h` and can be invoked on basic block translation or execution (in a configureable manner), in the QEMU Translation Engine (`accel/tcg/cpu-exec.c`) 

**Orchestrator**. It is implemented by the function `qemu_fuzzing_loop()` invoked into the `/softmmu/main.c`, which starts a new thread within the QEMU process.

**AFL Engine**. It integrates the libAFL library into FuzzBox design, and all the files are located in the folder `/qemu/libAFL`.


# QEMU FuzzBox patch
This directory includes the QEMU patch for building FuzzBox. In the following, we describe all steps to install the patch.

These steps are not necessary if you simply want to launch the IoT Firmware fuzzing experiment (i.e., build_n_go_firmware.sh), using the pre-patched QEMU provided in this repository.


## 1. System requirements and software dependencies
The testbed can be installed on a physical or virtual machine. You need to install the necessary dependencies for QEMU:
```
apt-get install ninja-build;
apt-get install pkg-config;
apt-get install libglib2.0-dev;
apt-get install libpixman-1-dev; 
apt-get install libfdt-dev;
```

## 2. Patching QEMU
You need to obtain the QEMU source code. The version of QEMU used is QEMU Adacore 7.0 

```
wget https://github.com/AdaCore/qemu/archive/refs/heads/qemu-stable-7.0.0.zip;
unzip qemu-stable-7.0.0.zip;
rm qemu-stable-7.0.0.zip;
mv qemu-qemu-stable-7.0.0/ qemu/;
```

Before building QEMU, remember to apply the patch provided in this repo by running the following command in the QEMU parent folder, after moving the patch into the same folder:
```
patch -p0 -i qemu.patch
```

## 3. Building QEMU from scratch
To configure QEMU, simply run the provided configure script using the followin command:
```
cd qemu;
mkdir build;
cd build;
../configure --target-list="aarch64-softmmu arm-softmmu ppc64-softmmu ppc-softmmu" --disable-xen --enable-plugins;
```

To build all Xen components you can use the ``make`` command. You can optionally use ``-j`` option to specify the number of jobs to run simultaneously (num_cpu + 1). 
```
make -j8;
```

Then you can use the following to install QEMU:
```
make install;
```


If while building you notice you don't have Meson (optional):
```
wget https://github.com/mesonbuild/meson/archive/0.59.3.tar.gz
tar -xzvf 0.59.3.tar.gz
cd meson-0.59.3
python3 setup.py build
sudo python3 setup.py install
sudo apt-get install meson
sudo ../configure --target-list="aarch64-softmmu arm-softmmu ppc64-softmmu ppc-softmmu" --disable-xen --enable-plugins --meson=/usr/bin/meson;
```

## 3. Compile TCG custom plugin 
```
cd fuzzbox_patch;
cd plugins;
make;
```

Create a virtual disk (not needed if already created)
```
qemu-img create -f raw disk.img 5G
```
