print("Booting up and engaging PyOS")
print("Copyright Wezhawk 2025")

VERSION = 1.0

import os
from datetime import datetime
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import curses
import sys
import requests
import subprocess

print("Preparing Colors...")
# <editor-fold desc="ANSI escape codes for text colors">
ESC = '\x1b'
RED = ESC + '[31m'
RED_BOLD = ESC + '[31;1m'
RED_HIGHLIGHT = ESC + '[41m'
ORANGE = ESC + '[38;5;208m'
ORANGE_BOLD = ESC + '[38;5;208;1m'
ORANGE_HIGHLIGHT = ESC + '[48;5;208m'
YELLOW = ESC + '[33m'
YELLOW_BOLD = ESC + '[33;1m'
YELLOW_HIGHLIGHT = ESC + '[43m'
GREEN = ESC + '[32m'
GREEN_BOLD = ESC + '[32;1m'
GREEN_HIGHLIGHT = ESC + '[42m'
BLUE = ESC + '[34m'
BLUE_BOLD = ESC + '[34;1m'
BLUE_HIGHLIGHT = ESC + '[44m'
PURPLE = ESC + '[35m'
PURPLE_BOLD = ESC + '[35;1m'
PURPLE_HIGHLIGHT = ESC + '[45m'
CYAN = ESC + '[36m'
CYAN_BOLD = ESC + '[36;1m'
CYAN_HIGHLIGHT = ESC + '[46m'
PINK = ESC + '[38;5;205m'
PINK_BOLD = ESC + '[38;5;205;1m'
PINK_HIGHLIGHT = ESC + '[48;5;205m'
TEAL = ESC + '[38;5;23m'
TEAL_BOLD = ESC + '[38;5;23;1m'
TEAL_HIGHLIGHT = ESC + '[48;5;23m'
BROWN = ESC + '[38;5;130m'
BROWN_BOLD = ESC + '[38;5;130;1m'
BROWN_HIGHLIGHT = ESC + '[48;5;130m'
MAGENTA = ESC + '[35m'
MAGENTA_BOLD = ESC + '[35;1m'
MAGENTA_HIGHLIGHT = ESC + '[45m'
LIME = ESC + '[38;5;119m'
LIME_BOLD = ESC + '[38;5;119;1m'
LIME_HIGHLIGHT = ESC + '[48;5;119m'
MAROON = ESC + '[38;5;88m'
MAROON_BOLD = ESC + '[38;5;88;1m'
MAROON_HIGHLIGHT = ESC + '[48;5;88m'
NAVY = ESC + '[38;5;17m'
NAVY_BOLD = ESC + '[38;5;17;1m'
NAVY_HIGHLIGHT = ESC + '[48;5;17m'
OLIVE = ESC + '[38;5;142m'
OLIVE_BOLD = ESC + '[38;5;142;1m'
OLIVE_HIGHLIGHT = ESC + '[48;5;142m'
TURQUOISE = ESC + '[38;5;80m'
TURQUOISE_BOLD = ESC + '[38;5;80;1m'
TURQUOISE_HIGHLIGHT = ESC + '[48;5;80m'
GRAY = ESC + '[38;5;240m'
RESET = ESC + '[0m'
# </editor-fold>

print("Loading Critical Functions...")
def get_time_stamp():
    current_datetime = datetime.now()
    return str(current_datetime)

def create_folder(namepath: str, log_action=True):
    if folder_exists(namepath):
        return False
    PyOS_system_lines.append(".folder")
    PyOS_system_lines.append(namepath)
    # Add initial metadata or leave blank
    PyOS_system_lines.append(f"CREATED: {get_time_stamp()}")
    PyOS_system_lines.append(".end")
    if log_action:
        log("Created Folder " + namepath, process="System")
    return True

def folder_exists(namepath: str):
    for i in range(len(PyOS_system_lines)):
        if PyOS_system_lines[i].startswith(".folder"):
            if i + 1 < len(PyOS_system_lines) and PyOS_system_lines[i + 1] == namepath:
                return True
    return False

def delete_folder(namepath: str, log_action=True):
    for i in range(len(PyOS_system_lines)):
        if PyOS_system_lines[i] == ".folder" and i + 1 < len(PyOS_system_lines):
            if PyOS_system_lines[i + 1] == namepath:
                start_index = i
                index = i + 2
                while index < len(PyOS_system_lines) and PyOS_system_lines[index] != ".end":
                    index += 1
                end_index = index
                del PyOS_system_lines[start_index:end_index + 1]
                if log_action:
                    log("Deleted Folder " + namepath, process="System")
                return True
    if log_action:
        log("Failed to delete folder " + namepath, process="System")
    return False

def create_file(namepath: str, contents, log_action=True):
    path_parts = namepath.split('/')
    folders = path_parts[:-1]
    for i in range(len(folders)):
        current_path = "/".join(folders[:i + 1])
        if not folder_exists(current_path):
            create_folder(current_path)

    if file_exists(namepath):
        return False

    PyOS_system_lines.append(".file")
    PyOS_system_lines.append(namepath)
    for line in contents:
        PyOS_system_lines.append(line)
    PyOS_system_lines.append(".end")

    if log_action:
        log("Created File " + namepath, process="System")
    return True

def file_exists(namepath):
    for i in range(len(PyOS_system_lines)):
        if PyOS_system_lines[i].startswith(".file"):
            if i + 1 < len(PyOS_system_lines) and PyOS_system_lines[i + 1] == namepath:
                return True

def update_file(namepath: str, updated_contents, log_action=True):
    for i in range(len(PyOS_system_lines)):
        if PyOS_system_lines[i] == ".file" and PyOS_system_lines[i + 1] == namepath:
            start_index = i + 2
            for j in range(start_index, len(PyOS_system_lines)):
                if PyOS_system_lines[j] == ".end":
                    end_index = j
                    break
            else:
                if log_action:
                    log("Failed to update file: missing .end in " + namepath, process="System")
                return False
            PyOS_system_lines[start_index:end_index] = updated_contents
            if log_action:
                log("Updated file " + namepath, process="System")
            return True

    create_file(namepath, updated_contents, log_action=log_action)
    if log_action:
        log("File did not exist. Created new file: " + namepath, process="System")
    return True

def read_file(namepath: str, log_action=False):
    for i in range(len(PyOS_system_lines)):
        if PyOS_system_lines[i] == ".file" and i + 1 < len(PyOS_system_lines):
            if PyOS_system_lines[i + 1] == namepath:
                read_content = []
                index = i + 2
                while index < len(PyOS_system_lines) and PyOS_system_lines[index] != ".end":
                    read_content.append(PyOS_system_lines[index])
                    index += 1
                if log_action:
                    log("Read file " + namepath, process="System")
                return read_content
    if log_action:
        print("Failed to read file " + namepath)
        log("Failed to read file " + namepath, process="System")
    return False

def append_file(namepath: str, content_to_append, log_action=True):
    original_file = read_file(namepath)
    for line in content_to_append:
        original_file.append(line)
    update_file(namepath, original_file, log_action=log_action)
    if log_action:
        log("Appended File " + namepath, process="System")
    return True

def copy_file(namepath: str, new_namepath: str, log_action=True):
    if file_exists(namepath):
        old_file_contents = read_file(namepath)
    else:
        print("File does not exist!")
        return False
    create_file(new_namepath, old_file_contents, log_action=False)
    if log_action:
        log(f"Copied File {namepath} to {new_namepath}", process="System")
    return True

def delete_file(namepath: str, log_action=True):
    for i in range(len(PyOS_system_lines)):
        if PyOS_system_lines[i] == ".file" and i + 1 < len(PyOS_system_lines):
            if PyOS_system_lines[i + 1] == namepath:
                index = i + 2
                while index < len(PyOS_system_lines) and PyOS_system_lines[index] != ".end":
                    index += 1
                del PyOS_system_lines[i: index + 1]
                if log_action:
                    log("Deleted File " + namepath, process="System")
                return True
    if log_action:
        print("Failed to delete file " + namepath)
        log("Failed to delete file " + namepath, process="System")
    return False

def log(to_log, process="Default"):
    log_entry = f"{PURPLE}({process}) {RESET}{get_time_stamp()}: {str(to_log)}"
    append_file("log.txt", [log_entry], log_action=False)
    return True

def list_directory_contents(directory, log_action=False):
    contents = []
    if directory.strip() == "":
        for i in range(len(PyOS_system_lines)):
            line = PyOS_system_lines[i]
            if line == ".file" and i + 1 < len(PyOS_system_lines):
                file_path = PyOS_system_lines[i + 1]
                if "/" not in file_path:
                    contents.append(file_path)
            elif line == ".folder" and i + 1 < len(PyOS_system_lines):
                folder_path = PyOS_system_lines[i + 1]
                if "/" not in folder_path:
                    contents.append(folder_path)
    else:
        dir_prefix = directory.rstrip("/") + "/"
        for i in range(len(PyOS_system_lines)):
            line = PyOS_system_lines[i]
            if line == ".file" and i + 1 < len(PyOS_system_lines):
                file_path = PyOS_system_lines[i + 1]
                sub_path = file_path[len(dir_prefix):]
                if file_path.startswith(dir_prefix) and "/" not in sub_path:
                    contents.append(file_path)
            elif line == ".folder" and i + 1 < len(PyOS_system_lines):
                folder_path = PyOS_system_lines[i + 1]
                sub_path = folder_path[len(dir_prefix):]
                if folder_path.startswith(dir_prefix) and "/" not in sub_path:
                    contents.append(folder_path)
    if log_action:
        log("Listed contents of directory: " + directory, process="System")
    return contents

def get_config_variables(filepath='system/config', log_action=False):
    config_data = read_file(filepath)
    if not config_data:
        if log_action:
            log(f"Failed to load config from {filepath}", process="System")
        return {}
    config_vars = {}
    for line in config_data:
        if ":" in line:
            key, value = line.split(":", 1)
            config_vars[key.strip()] = value.strip()
    if log_action:
        log(f"Loaded config from {filepath}", process="System")
    return config_vars

def set_config_variable(key, value, filepath='system/config', log_action=True):
    config_data = read_file(filepath)
    updated_lines = []
    found = False
    if config_data:
        for line in config_data:
            if ":" in line:
                existing_key, _ = line.split(":", 1)
                if existing_key.strip() == key:
                    updated_lines.append(f"{key}: {value}")
                    found = True
                else:
                    updated_lines.append(line)
            else:
                updated_lines.append(line)
    if not found:
        updated_lines.append(f"{key}: {value}")
    success = update_file(filepath, updated_lines, log_action=False)
    if log_action:
        if success:
            action = "Updated" if found else "Added"
            log(f"{action} config variable '{key}' in {filepath}", process="System")
        else:
            print("Failed to update config variable")
            log(f"Failed to update config variable '{key}' in {filepath}", process="System")
    return success

def generate_key_from_password(password: str, salt: bytes = None):
    if not salt:
        salt = os.urandom(16)  # Save this salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def save_system(password: str, filename="PyOS-system", saltfile="PyOS_salt.bin", log_action=True):
    key, salt = generate_key_from_password(password)

    # Save the salt for future decryption
    with open(saltfile, "wb") as sfile:
        sfile.write(salt)

    # Convert to byte string
    raw_data = "\n".join(PyOS_system_lines).encode()
    encrypted = Fernet(key).encrypt(raw_data)

    # Save encrypted system
    with open(filename, "wb") as file:
        file.write(encrypted)

    if log_action:
        log(f"Encrypted system saved to {filename}", process="Save Service")
    return True

def load_system(password: str, filename="PyOS-system", saltfile="PyOS_salt.bin", log_action=True):
    try:
        with open(saltfile, "rb") as sfile:
            salt = sfile.read()

        key, _ = generate_key_from_password(password, salt)

        with open(filename, "rb") as file:
            encrypted = file.read()

        decrypted_data = Fernet(key).decrypt(encrypted).decode()
        lines = decrypted_data.split("\n")

        global PyOS_system_lines
        PyOS_system_lines = lines

        if log_action:
            log(f"System loaded and decrypted from {filename}", process="Load Service")
        return True

    except Exception as e:
        print("Decryption failed:", e)
        if log_action:
            print(RED + "Failed to load encrypted system!\nQuitting!" + RESET)
            exit()
        return False


def check_internet(url="http://www.google.com", timeout=5):
    try:
        requests.get(url, timeout=timeout)
        return True
    except (requests.ConnectionError, requests.Timeout):
        return False


def download_file(file_url, file_name, log_action=True, process="System"):
    if not check_internet():
        if log_action:
            log("No internet connection!", process)
        return False
    try:
        print("Downloading file...")
        response = requests.get(file_url, stream=True)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)

        with open(file_name, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:  # Filter out keep-alive new chunks
                    file.write(chunk)
        if log_action:
            log(f"File '{file_name}' downloaded successfully.", process)
        return True

    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {e}")
        if log_action:
            log("Error downloading file " + file_name, process)
        return False


def create_os():
    global PyOS_system_lines
    PyOS_system_lines = ["PyOS-valid", "Created: " + get_time_stamp(), ""]

    print("Creating initial file structure...")
    create_file("log.txt", [PURPLE + "(System) " + RESET + f"{get_time_stamp()}: Created File log.txt"],
                log_action=False)
    create_folder("system")
    create_folder("system/packages")
    create_file("system/packages/installed_packages", [])
    create_file("test.txt", ["This is a test file", "PyOS version 1.0"])
    create_file("system/command_list",
                ["log", "mkdir", "read", "cd", "ls", "del", "run", "cp", "exit", "shutdown", "system", "commands",
                 "help", "passwd", "edit", "package"])
    create_file("system/config", [f"VERSION: {VERSION}", f"USERNAME: {username}"])
    create_file("system/message_queue", [])
    print(GREEN + "Finished creating initial file structure" + RESET)
    print("Booting into OS...")

print("Getting Time...")
print(get_time_stamp())

print("Checking update...")
if sys.argv > 1:
    if sys.argv[1] == "updated":
        print("Successfully updated!")
        print("Continuing boot...")
if download_file("https://raw.githubusercontent.com/Wezhawk/PyOS/main/update/version", "version",
                 process="Update Helper"):
    f = open("version", "r")
    contents = f.read()
    try:
        current_version = int(contents)
    except Exception as e:
        print("Error: " + str(e))
    else:
        if current_version > VERSION:
            os.remove("version")
            print("You are using an outdated version of PyOS")
            log("Newer system version detected", "Update Helper")
            conf = ""
            while conf not in ["y", "n"]:
                conf = input("Would you like to update? [y or n]")
            if conf == "n":
                print("The system will not update")
                print("Continuing boot...")
                log("Not updating system", process="Update Helper")
            elif conf == "y":
                print("Preparing to download and launch update helper")
                log("Updating system", process="Update Helper")
                if download_file("https://raw.githubusercontent.com/Wezhawk/PyOS/main/update/update_helper.py",
                                 "update_helper.py", process="Update Helper"):
                    subprocess.run(["python", "update_helper.py"])
                    print("Exiting...")
                    exit()
                else:
                    print("Could not download update!")
                    print("Continuing boot...")
                    log("Could not download update file", process="Update Helper")

print("Checking for sysfile...")
if os.path.isfile("PyOS-system"):
    password = input("Enter PyOS password to decrypt system: ")
    if load_system(password):
        print("System successfully loaded.")
    else:
        print("Invalid password or corrupted save file.")

    config = get_config_variables()
    username = config.get("USERNAME")

    set_config_variable("VERSION", VERSION)
else:
    print(ORANGE + "Warning: Sysfile does not exist" + RESET)
    initial_session = True
    print("Preparing to create OS...\n\n\n")
    password = input(GREEN_BOLD + "What would you like your master password to be: " + BLUE)
    if " " in password:
        print(RED + "Master password cannot contain spaces!" + RESET)
        print(RED + "Exiting Now!" + RESET)
    salt = os.urandom(16)
    key, _ = generate_key_from_password(password, salt)
    with open("PyOS_salt.bin", "wb") as sfile:
        sfile.write(salt)

    username = input(GREEN_BOLD + "What would you like your username to be: " + BLUE)
    print(RESET)
    print(PURPLE + "(System) " + RESET + "Starting task CreateOS")

    create_os()

print("Setting current directory...")
current_directory = ""

print("Preparing non-critical functions...")


def show_and_handle_prompt():
    global current_directory
    user_input = input(username + "@PyOS " + current_directory + " > ")
    command_list = read_file("system/command_list")
    for command in command_list:
        if user_input.startswith(command):
            handle_command(user_input)
            return
    print(
        "Command not recognized. \nTo run a script, type 'run <script name>' \nTo access a list a commands type 'commands'\n\n")
    return False

def handle_command(user_input):
    global current_directory
    global PyOS_system_lines
    arguments = user_input.strip().split(" ")
    if arguments[0] == "log":
        if len(arguments) == 1:
            current_log = read_file("log.txt")
            if current_log:
                for line in current_log:
                    print(line)
            else:
                print("Log is empty or missing.")
        else:
            if arguments[1] == "clear":
                print("Warning! Clearing log")
                update_file("log.txt", [], log_action=False)
                log("Cleared log", process="System")
            message_to_log = " ".join(arguments[1:])
            log(message_to_log, process="User")
        return True
    elif arguments[0] == "mkdir":
        if len(arguments) < 2:
            print("Error! Please enter a folder name.\nUsage: mkdir <folder>")
            return False
        create_folder(arguments[1])
        return True
    elif arguments[0] == "read":
        if len(arguments) < 2:
            print("Please enter a file to read")
            return False
        file_to_read = read_file(arguments[1])
        if not file_to_read:
            print("File could not be found")
            return False
        for line in file_to_read:
            print(line)
        return True
    elif arguments[0] == "cd":
        if len(arguments) < 2:
            current_directory = ""
            return True
        if folder_exists(arguments[1]):
            current_directory = arguments[1]
            return True
        else:
            print("Folder not found.")
            return False
    elif arguments[0] == "ls":
        directory_to_list = arguments[1] if len(arguments) > 1 else current_directory
        contents = list_directory_contents(directory_to_list)
        for line in contents:
            print(line)
        return True
    elif arguments[0] == "del":
        if len(arguments) < 2:
            print("Please enter a filename to delete\nUsage: del <filename>")
            return False
        if file_exists(arguments[1]):
            delete_file(arguments[1])
            return True
        else:
            print("File does not exist!")
            return False
    elif arguments[0] == "cp":
        if len(arguments) < 3:
            print("Please enter a filepath to copy from and to\nUsage: cp <file to copy> <file to create>")
            return False
        copy_file(arguments[1], arguments[2])
        return True
    elif arguments[0] == "commands":
        command_list = read_file("system/command_list")
        for line in command_list:
            print(line)
    elif arguments[0] == "shutdown":
        shutdown_os()
        return True
    elif arguments[0] == "exit":
        exit_os()
        return True
    elif arguments[0] == "passwd":
        global password
        if len(arguments) < 2:
            print("Please enter a new password\nUsage: passwd <new password>")
            return False
        old_pass = input("Please enter your current password: ")
        if old_pass != password:
            print("Current password is not valid!")
            log("Attempted change of password. Current password not valid.", process="Security Service")
        save_system(old_pass, arguments[1])
        password = arguments[1]
        print("Password updated and system re-encrypted.")
        log("System password changed successfully", process="Security Service")
        return True
    elif arguments[0] == "edit":
        if len(arguments) < 2:
            print("Please enter a file to edit or create\nUsage: edit <file>")
            return False
        text_editor_gui(arguments[1])
        return True
    elif arguments[0] == "package":
        print("Warning! This command is not complete. Use with caution!")
        if len(arguments) < 2:
            list_directory_contents("system/packages")
            return True
        elif arguments[1] == "register":
            # register_package()
            return True
        elif arguments[1] == "update":
            # update_package()
            return True
        else:
            print(
                "Subcommand not found\nUsage:\n\tpackage → lists current packages\n\tpackage register → registers a package\n\t package update → updates an existing package")
    elif arguments[0] == "run":
        print("Warning! This command is not complete. Use with caution!")
        if len(arguments) < 2:
            print("Please enter a script to run\nUsage: run <script>")
        if file_exists(arguments[1]):
            # run_script(arguments[1])
            return True
        else:
            print("File could not be found!")
            return False
    elif arguments[0] == "help":
        if len(arguments) < 2:
            print("To access a list of commands, type 'commands'")
            print("If you would like help with a specific command, type 'help <command>'")
            return True
        else:
            command_help_text = {
                "log": "View or add to the system log.\nUsage:\n  log            → displays the contents of log.txt\n  log <message>  → adds the message to log.txt\n  log clear  → clears the log",
                "package": "Interfaces with packages\nUsage:\n\tpackage →           lists current packages\n\tpackage register →            registers a package\n\t package update →       updates an existing package",
                "run": "Runs a scripts\nUsage: run <script>",
                "passwd": "Changes the system password\nUsage:\n  passwd <new password>",
                "edit": "Edits a file\nUsage: edit <file>",
                "mkdir": "Create a new folder in the filesystem.\nUsage:\n  mkdir <folder>",
                "read": "Display the contents of a file line by line.\nUsage:\n  read <filename>",
                "cd": "Change the current working directory.\nUsage:\n  cd <folder>\n  cd             → resets to root directory",
                "ls": "List files and folders within a directory.\nUsage:\n  ls             → lists current directory\n  ls <directory> → lists specified directory",
                "del": "Delete a file from the system.\nUsage:\n  del <filename>",
                "cp": "Copy the contents of one file to a new file.\nUsage:\n  cp <source> <destination>",
                "commands": "Display a list of all available commands.\nUsage:\n  commands",
                "shutdown": "Safely shut down the PyOS system.\nUsage:\n  shutdown",
                "exit": "Exit the PyOS system session.\nUsage:\n  exit",
                "help": "Access built-in help documentation.\nUsage:\n  help               → general help overview\n  help <command>     → detailed help for that command",
                "system": "Run advanced system commands.\nUsage:\n  system messages    → view system messages\n  system post <message>    → post a system message\n  system save        → save current system state\n  system print       → output the internal system list\n  system purge       → wipe and regenerate OS (requires confirmation)"
            }
            print(command_help_text[arguments[1]])
    elif arguments[0] == "system":
        if len(arguments) < 2:
            print("Please enter a system command: messages, save, or print")
            return False
        if arguments[1] == "messages":
            for line in get_system_messages():
                print(line)
            return True
        elif arguments[1] == "save":
            save_state()
            return True
        elif arguments[1] == "print":
            for line in PyOS_system_lines:
                print(line)
            return True
        elif arguments[1] == "purge":
            conf = ""
            while conf not in ["y", "n"]:
                conf = input(
                    "Are you sure you want to purge the system?\n(Will not change master password) [y or n]: ").lower()
            if conf == 'y':
                print("Preparing to purge and recreate OS...")
                PyOS_system_lines = []
                create_os()
                save_state()
                return True
            elif conf == 'n':
                print("Canceling...")
                return False
        elif arguments[1] == "post":
            if len(arguments) < 3:
                print("Please enter a message to post")
                return False
            else:
                post_system_message(arguments[2], process="User")
        else:
            print("Subcommand not found!")
            print(
                "Usage:\n  system messages    → view system messages\n  system post <message>    → post a system message\n  system save        → save current system state\n  system print       → output the internal system list\n  system purge       → wipe and regenerate OS (requires confirmation)")
    return False

def get_system_messages():
    current_system_messages = read_file("system/message_queue")
    update_file("system/message_queue", [], log_action=False)
    log("Collected and cleared current system messages", process="Message Service")
    return current_system_messages

def post_system_message(message_content, process="Default"):
    append_file("system/message_queue", [PURPLE + f"({process}) " + RESET + str(message_content)], log_action=False)
    log(f"Posted new system message by process {process}", process="Message Service")
    return True

def text_editor_gui(namepath: str):
    contents = read_file(namepath) or [""]

    def main(stdscr):
        cursor_y = 0
        cursor_x = 0
        curses.curs_set(1)
        stdscr.keypad(True)
        while True:
            stdscr.clear()
            stdscr.addstr(0, 0, f"Editing: {namepath} — Ctrl+O=Save | Ctrl+X=Exit")
            for i, line in enumerate(contents):
                stdscr.addstr(i + 1, 0, line)
            stdscr.move(cursor_y + 1, cursor_x)
            stdscr.refresh()
            key = stdscr.getch()
            if key == 24:  # Ctrl+X
                break
            elif key == 15:  # Ctrl+O
                update_file(namepath, contents)
                log(f"Saved file from nano GUI: {namepath}", process="Nano")
            elif key == curses.KEY_DOWN and cursor_y < len(contents) - 1:
                cursor_y += 1
                cursor_x = min(cursor_x, len(contents[cursor_y]))
            elif key == curses.KEY_UP and cursor_y > 0:
                cursor_y -= 1
                cursor_x = min(cursor_x, len(contents[cursor_y]))
            elif key == curses.KEY_LEFT and cursor_x > 0:
                cursor_x -= 1
            elif key == curses.KEY_RIGHT and cursor_x < len(contents[cursor_y]):
                cursor_x += 1
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                if cursor_x > 0:
                    contents[cursor_y] = (
                            contents[cursor_y][:cursor_x - 1] + contents[cursor_y][cursor_x:]
                    )
                    cursor_x -= 1
            elif key in (10, 13):  # Enter key (LF or CR)
                line = contents[cursor_y]
                before = line[:cursor_x]
                after = line[cursor_x:]
                contents[cursor_y] = before
                contents.insert(cursor_y + 1, after)
                cursor_y += 1
                cursor_x = 0
            elif 32 <= key <= 126:  # Printable ASCII
                line = contents[cursor_y]
                contents[cursor_y] = line[:cursor_x] + chr(key) + line[cursor_x:]
                cursor_x += 1

    curses.wrapper(main)

def save_state():
    print("Preparing to save state and encrypt...")
    save_system(password)

def shutdown_os():
    print("Preparing to save state and exit...")
    save_state()
    print("Saved State")
    print("Exiting PyOS...")
    exit()

def exit_os():
    conf = ""
    while conf not in ["y", "n"]:
        conf = input("Are you sure you want to quit and not save? [y or n]: ").lower()
    if conf == "y":
        print("Preparing to exit OS...")
        exit()
    else:
        print("Canceling...")
        return False

print("Preparing OS Interface...")
print("\n\n")
print("Welcome to PyOS!")
print("System messages and alerts will be displayed here on bootup or on demand using 'system messages'")
for message in get_system_messages():
    print(message)

while True:
    try:
        prompt = show_and_handle_prompt()
        if prompt == "shutdown":
            break
    except KeyboardInterrupt:
        print("\nCTRL+C Detected")
        print("System notice: Please use the 'shutdown' command to close PyOS cleanly.")
        log("User attempted shutdown via Ctrl+C", process="UI")