#!/bin/bash

usage() {
    echo "Usage: $0 -d <directory> [-r|--regex <regex> | -j|--json <json file> | -f|--fuzz-all <regex>] [-a|--analyze] [-h|--help]"
    echo "  -d, --directory <directory>   Specify the target directory."
    echo "  -r, --regex <regex>           Specify the regex pattern with curly braces surrounding the fuzzed part (mutually exclusive with -j and -f)."
    echo "  -j, --json <json file>        Specify the JSON file for more control over what to write and what to fuzz (mutually exclusive with -r and -f)."
    echo "  -f, --fuzz-all <regex>        Specify the regex pattern for fuzzing of the whole payload (mutually exclusive with -r and -j)."
    echo "  -a, --analyze                 Activate analyze mode to read all incoming packets."
    echo "  -h, --help                    Display this help message."
    exit 1
}

target_dir=""
regex=""
json=""
fuzz=""
analyze=""

while [ "$#" -gt 0 ]; do
    case $1 in
        -d|--directory)
            target_dir="$2"
            if [ ! -d "$target_dir" ]; then
                echo "Error: The directory specified for -d/--directory does not exist."
                usage
            fi
            shift 2
            ;;
        -r|--regex)
            if [ -n "$json" ] || [ -n "$fuzz" ]; then
                echo "Error: -r/--regex, -j/--json, and -f/--fuzz-all are mutually exclusive."
                usage
            fi
            regex="$2"
            shift 2
            ;;
        -j|--json)
            if [ -n "$regex" ] || [ -n "$fuzz" ]; then
                echo "Error: -r/--regex, -j/--json, and -f/--fuzz-all are mutually exclusive."
                usage
            fi
            json="$2"
            if [ ! -f "$json" ]; then
                echo "Error: The file specified for -j/--json does not exist."
                usage
            fi
            json=$(realpath "$json")
            shift 2
            ;;
        -f|--fuzz-all)
            if [ -n "$regex" ] || [ -n "$json" ]; then
                echo "Error: -r/--regex, -j/--json, and -f/--fuzz-all are mutually exclusive."
                usage
            fi
            fuzz="$2"
            shift 2
            ;;
        -a|--analyze)
            analyze="true"
            shift 1
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Unknown parameter passed: $1"
            usage
            ;;
    esac
done

if [ -z "$target_dir" ]; then
    echo "Error: -d/--directory is required."
    usage
fi

current_dir=$(pwd)
cd $target_dir
target_dir=$(pwd)
cd $current_dir

# Remove the existing seed link if it exists
rm -f "seeds/seed"

# Create the symbolic link
ln -s $target_dir/seed $current_dir/seeds/seed

cd ..
cd qemu
mkdir build
cd build 
find /home/carmine/projects/workspace_fuzzbox/FuzzBox -type f -name "*.sh" -exec chmod +x {} \;
clear
chmod +x ../configure
chmod +x ../scripts/git-submodule.sh
chmod +x ../tests/tcg/configure.sh
#../configure --target-list="mips-softmmu mips64-softmmu mips64el-softmmu mipsel-softmmu aarch64-softmmu arm-softmmu" --disable-xen --enable-plugins 
../configure --target-list="mips-softmmu mipsel-softmmu arm-softmmu" --disable-xen --enable-plugins 
sudo make -j8
sudo make install
cd ..
cd ..
cd usr

params=("-d" "$target_dir")
if [ -n "$regex" ]; then
    params+=("-r" "$regex")
elif [ -n "$json" ]; then
    params+=("-j" "$json")
elif [ -n "$fuzz" ]; then
    params+=("-f" "$fuzz")
fi

if [ -n "$analyze" ]; then
    params+=("--analyze")
fi

sudo bash ./start_firmware.sh "${params[@]}"
