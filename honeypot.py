# honeypot.py
# driver for the fake ssh / honeypot
import logging
import os
import re
import socket
import threading
import time

import paramiko # (I'm not cracked enough to rewrite SSH transport... yet)

HOST_KEY_FILE = "host_key.pem"
CUSTOM_BANNER = "SSH-2.0-OpenSSH_9.9p2 Debian-1"
FAKE_CREDENTIALS = { "dguy":"dguh", "admin":"password123", "root":"fullpower" }

logging.basicConfig(filename="honeypot.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def load_or_gen_host_key():
    if os.path.exists(HOST_KEY_FILE):
        print("Loading existing SSH host key")
        return paramiko.RSAKey(filename=HOST_KEY_FILE)
    else:
        print("Generating new SSH host key")
        host_key = paramiko.RSAKey.generate(2048)
        host_key.write_private_key_file(HOST_KEY_FILE)
        return host_key

HOST_KEY = load_or_gen_host_key()

def log_attempt(client_ip, username, password):
    logging.info(f"Login attempt from {client_ip}, User: {username}, Pass: {password}")
    print(f"[i] Logged attempt from {client_ip} with {username}:{password}")

def log_success(client_ip, username, password):
    logging.info(f"Login 'SUCCESS' from {client_ip}, User: {username}, Pass: {password}")
    print(f"[$] Login 'SUCCESS' from {client_ip}, User: {username}, Pass: {password}")

def log_message(message):
    logging.info(message)
    print(f"[m] {message}")

class HoneypotHandler(paramiko.ServerInterface):
    """Handler subclass for the honeypot server."""
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_attempt(self.client_ip, username, password)
        if username in FAKE_CREDENTIALS and FAKE_CREDENTIALS[username] == password:
            log_success(self.client_ip, username, password)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        log_attempt(self.client_ip, username, f"pubkey: {key.get_base64()[:20]}...")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
            return "publickey,password"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self.pty_term = term
        self.pty_width = width
        self.pty_height = height
        return True

class HoneypotTransport(paramiko.Transport):
    """Transport subclass to enforce immediate disconnect on invalid content."""
    def _check_banner(self):
        """Enforces immediate disconnect on invalid SSH banner. Only reads one line."""
        client_ip = self.sock.getpeername()[0]
        try:
            buf = self.packetizer.readline(self.banner_timeout) # Read only one line
        except Exception as e:
            raise paramiko.SSHException("Error reading SSH protocol banner" + str(e))

        self._log(paramiko.common.DEBUG, f"Banner: {buf}")
        match = re.match(r"SSH-(\d+\.\d+)-(.*)", buf)
        if match is None:
            print(f"[-] Invalid SSH identification string from {client_ip}, closing connection.")
            try:
                self.sock.sendall(b"Invalid SSH identification string.\n")
            except:
                pass
            self.close()
            raise paramiko.SSHException(f"Invalid SSH Banner: {buf}")

        self.remote_version = buf
        self._log(paramiko.common.DEBUG, f"Remote version/idstring: {self.remote_version}")

        i = buf.find(" ")
        if i >= 0:
            buf = buf[:i]

        segs = buf.split("-", 2)
        if len(segs) < 3:
            raise paramiko.SSHException("Invalid SSH banner")
        version = segs[1]
        client = segs[2]
        if version != "1.99" and version != "2.0":
            msg = f"Incompatible version ({version} instead of 2.0)"
            raise paramiko.ssh_exception.IncompatiblePeer(msg)
        msg = f"Connected (version {version}, client {client})"
        self._log(paramiko.common.INFO, msg)
        print(f"[++] Valid SSH banner received from {client_ip}: {self.remote_version}")


def handle_fake_command(command, user):
    command = command.strip()

    if not command:
        return "", False # Print prompt again

    if command in ["exit", "logout"]:
        return "logout", True
    elif command == "whoami":
        return f"{user}", False
    elif command.startswith("cd"):
        return "", False
    elif command.startswith("ls"):
        if "-la" in command or "-al" in command:
            return "drwxr-xr-x  2 dguy dguy 4096 Apr  1 17:00 .\r\n" + \
                   "drwxr-xr-x 15 root root 4096 Apr  1 17:00 ..\r\n" + \
                   "-rw-r--r--  1 dguy dguy   23 Apr  1 18:01 README.md\r\n" + \
                   "-rw-r--r--  1 dguy dguy   42 Apr  1 18:02 passwords.txt", False
        elif "-a" in command:
            return ".  ..  dguy.png  README.md  temp.txt  passwords.txt", False
        elif "-l" in command:
            return "-rw-r--r--  1 dguy dguy   23 Apr  1 18:01 README.md\r\n" + \
                   "-rw-r--r--  1 dguy dguy   42 Apr  1 18:02 passwords.txt", False
        return "dguy.png  README.md  temp.txt  passwords.txt", False
    elif command.startswith("man"):
        return "I hope you know what you're doing if you made it this far...", False
    elif command.startswith("cat"):
        fake_files = {
            "README.md": "# Welcome!\r\nYou successfully cat the readme file. Have fun looking around!",
            "passwords.txt": "dguy:dguh\r\nadmin:password123\r\nroot:fullpower",
            "temp.txt": "This is a temp file!"
        }
        parts = command.split()
        if len(parts) > 1 and parts[1] in fake_files:
            return fake_files[parts[1]], False
        return f"cat: {parts[1] if len(parts) > 1 else ''}: No such file or directory", False
    elif command.startswith("su"):
        time.sleep(2)
        return "su: Authentication failure", False
    else:
        return f"-bash: {command}: command not found", False

def handle_fake_shell(chan, user):
    """Let the trolling begin"""
    GREEN = "\x1b[1;32m"
    BLUE = "\x1b[1;34m"
    RESET = "\x1b[0m"
    SHELL_STRING = f"{GREEN}{user}@dguyserv{RESET}:{BLUE}~{RESET}$ "
    chan.send("Welcome to Debian GNU/Linux 11\n\r")
    chan.send(SHELL_STRING)

    buffer = ""
    history = []
    history_index = -1
    escape_seq = False
    escape_buffer = ""

    # TODO: Add disconnect timeout
    try:
        while True:
            data = chan.recv(1024)
            if not data:
                break

            for byte in data:
                char = chr(byte)

                if escape_seq:
                    escape_buffer += char
                    if len(escape_buffer) == 2:
                        # Arrow key handling
                        if escape_buffer == "[A": # Up
                            if history:
                                history_index = max(0, history_index - 1)
                                buffer = history[history_index]
                                chan.send(f"\r\x1b[2K{SHELL_STRING}{buffer}")
                        elif escape_buffer == "[B": # Down
                            if history:
                                history_index = min(len(history), history_index + 1)
                                buffer = history[history_index] if history_index < len(history) else ""
                                chan.send(f"\r\x1b[2K{SHELL_STRING}{buffer}")
                        escape_seq = False
                        escape_buffer = ""
                    continue

                if byte == 27: # ESC
                    escape_seq = True
                    escape_buffer = ""
                    continue
                if byte == 3: # Ctrl-C
                    buffer = ""
                    chan.send(f"^C\r\n{SHELL_STRING}")
                    continue
                elif byte == 4: # Ctrl-D
                    chan.send("\r\nlogout\r\n")
                    return
                elif byte in (10, 13): # Enter
                    chan.send("\r\n")
                    output, should_exit = handle_fake_command(buffer, user)
                    chan.send(output + "\r\n")
                    if buffer.strip():
                        history.append(buffer)
                    history_index = len(history)
                    if should_exit:
                        chan.send("logout\r\n")
                        return
                    buffer = ""
                    chan.send(SHELL_STRING)
                elif byte in (127, 8): # Backspace
                    if buffer:
                        buffer = buffer[:-1]
                        chan.send("\b \b") # Erase char
                elif 32 <= byte <= 126: # Printable chars
                    buffer += char
                    chan.send(char)

    except Exception as e:
        print(f"[!!] Exception in fake shell: {e}")
    finally:
        # TODO: Block IP
        chan.close()

def handle_client(client_socket, client_ip):
    try:
        transport = HoneypotTransport(client_socket)
        transport.local_version = CUSTOM_BANNER

        transport.add_server_key(HOST_KEY)
        server = HoneypotHandler(client_ip)

        transport.start_server(server=server)
        chan = transport.accept(120)
        if chan is None:
            raise Exception("No channel")

        if not transport.is_authenticated():
            raise Exception("Transport inactive before authentication")

        username = transport.get_username()
        if username:
            print(f"[+++] {client_ip} successfully 'logged in' as {username}")
            handle_fake_shell(chan, username)
    except Exception as e:
        print(f"[!] Exception for {client_ip}: {e}")
    finally:
        print(f"[---] Connection to {client_ip} closed.")
        client_socket.close()

def start_honeypot(host="0.0.0.0", port=2222):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"SSH Honeypot listening on {host}:{port}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"[+] Connection from {addr[0]}:{addr[1]}")
        threading.Thread(target=handle_client, args=(client_socket, addr[0])).start()


if __name__ == "__main__":
    start_honeypot()
