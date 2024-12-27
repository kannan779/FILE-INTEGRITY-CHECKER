import hashlib
import os
import time
from colorama import Fore, Back, Style, init
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit import prompt

init(autoreset=True)

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        print(f"{Fore.RED}Error reading file {file_path}: {e}")
        return None

def get_file_path(prompt_text):
    """Use prompt_toolkit to autocomplete file paths."""
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def monitor_file(file_path, check_interval=5):
    """Monitor the file for changes by comparing hash values."""
    print(f"{Fore.YELLOW}Monitoring changes for file: {file_path}")
    last_hash = None

    while True:
        current_hash = calculate_file_hash(file_path)
        if current_hash is None:
            print(f"{Fore.RED}Could not calculate hash for {file_path}. Skipping this check.")
            time.sleep(check_interval)
            continue

        if last_hash is None:
            last_hash = current_hash
            print(f"{Fore.GREEN}Initial hash calculated: {current_hash}")
        elif current_hash != last_hash:
            print(f"{Fore.RED}{Style.BRIGHT}File has changed!")
            print(f"{Fore.YELLOW}Previous Hash: {last_hash}")
            print(f"{Fore.GREEN}New Hash: {current_hash}")
            last_hash = current_hash
        
        time.sleep(check_interval)

if __name__ == "__main__":
    file_to_monitor = get_file_path("\nEnter the path of the file to monitor : ")

    check_interval = int(input(f"{Fore.CYAN}\nEnter the interval (in seconds) between checks: "))
    
    if not os.path.isfile(file_to_monitor):
        print(f"{Fore.RED}The specified file does not exist.")
    else:
        monitor_file(file_to_monitor, check_interval)
