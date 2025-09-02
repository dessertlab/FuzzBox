#!/bin/bash

# Funzione di aiuto
usage() {
    echo "Usage: $0 -d <directory> [-r|--regex <regex> | -j|--json <json file> | -f|--fuzz-all <regex>] [-a|--analyze] [-h|--help]"
    echo "  -d, --directory <directory>   Specify the target directory."
    echo "  -r, --regex <regex>           Specify the regex pattern with curly braces surrounding the fuzzed part (mutually exclusive with -j and -f)."
    echo "  -j, --json <json file>        Specify the JSON file for more control over what to write and what to fuzz (mutually exclusive with -r and -f)."
    echo "  -f, --fuzz-all <regex>        Specify the regex pattern forfuzzing of the whole payload (mutually exclusive with -r and -j)."
    echo "  -a, --analyze                 Activate analyze mode to read all incoming packets."
    echo "  -h, --help                    Display this help message."
    exit 1
}

# Inizializzazione variabili
target_dir=""
regex=""
json=""
fuzz=""
analyze=""

# Parsing degli argomenti
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

# Verifica che tutti i parametri necessari siano presenti
if [ -z "$target_dir" ]; then
    echo "Error: -d/--directory is required."
    usage
fi

find /dev/shm -type f -name '*sem*' -exec rm {} \; 
sudo chmod 0777 /dev/shm
cd ../fuzzbox_patch
cd plugins
make linux
cd ../../usr

# Prepara i parametri per script_firmware.sh
params=()
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

cd $target_dir && bash ./script_firmware.sh "${params[@]}"

