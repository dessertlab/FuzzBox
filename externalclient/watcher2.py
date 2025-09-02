import time

def monitor_file(file_path, output_file):
    with open(output_file, 'w') as output:
        output.write('0')

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        file.seek(0, 2)

        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)  # Aspetta un attimo se non ci sono nuove righe
                continue
            
            # Controlla se "Kernel panic" è nella riga
            if "Kernel panic" in line:
                with open(output_file, 'w') as output:
                    output.write('1')

if __name__ == "__main__":
    log_file_path = "/home/carmine/projects/workspace_fuzzbox/FuzzBox/externalclient/macOutput.txt"  # Sostituisci con il percorso del tuo file
    output_file_path = "/home/carmine/projects/workspace_fuzzbox/FuzzBox/externalclient/detected"  # Percorso del file di output
    monitor_file(log_file_path, output_file_path)
