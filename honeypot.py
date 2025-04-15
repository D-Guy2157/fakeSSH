# honeypot.py
# driver for the fake ssh / honeypot
import logging
import os
import re
import socket
import struct
import threading
import time
import requests
import signal
import sys
from dotenv import load_dotenv
import paramiko # (I'm not cracked enough to rewrite SSH transport... yet)

load_dotenv()

DISCORD_WEBHOOK = os.getenv("WEBHOOK")
BANNED_IPS_FILE = "banned_ips.txt"
HOST_KEY_FILE = "host_key.pem"
CUSTOM_BANNER = "SSH-2.0-OpenSSH_9.9p2 Debian-1"
FAKE_CREDENTIALS = { "dguy":"dguh", "admin":"password", "root":"fullpower"}
GREEN = "\x1b[1;32m"
BLUE = "\x1b[1;34m"
RESET = "\x1b[0m"

logging.basicConfig(filename="honeypot.log", level=logging.INFO, format="%(asctime)s - %(message)s")

try:
    with open(BANNED_IPS_FILE, "r") as f:
        BANNED_IPS = set(f.read().splitlines())
except FileNotFoundError:
    BANNED_IPS = set()

def graceful_shutdown(signum, frame):
    print("\n[!] Caught interrupt signal (Ctrl+C). Shutting down...")
    sys.exit(0)

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

def ban_ip(ip):
    BANNED_IPS.add(ip)
    log_message(f"(Ban) Banned IP: {ip}")
    with open(BANNED_IPS_FILE, "a") as f:
        f.write(ip + "\n")

def reset_connection(sock):
    """Force TCP RST"""
    try:
        linger = struct.pack('ii', 1, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
        sock.close()
    except Exception as e:
        print(f"[!] Error resetting connection: {e}")

def log_connection_ip(ip):
    with open("ips.log", "a") as f:
        f.write(ip + "\n")

def log_banned_attempt(client_ip):
    logging.info(f"{client_ip} is banned. Resetting connection.")
    print(f"[x] {client_ip} is banned. Resetting connection.")

def log_attempt(client_ip, username, password):
    logging.info(f"Login attempt from {client_ip}, User: {username}, Pass: {password}")
    print(f"[i] Logged attempt from {client_ip} with {username}:{password}")

def log_success(client_ip, username, password):
    logging.info(f"Login \"SUCCESS\" from {client_ip}, User: {username}, Pass: {password}")
    print(f"[$] Login \"SUCCESS\" from {client_ip}, User: {username}, Pass: {password}")
    ban_ip(client_ip)
    notify_discord(username, password, client_ip)

def log_command(client_ip, username, command):
    logging.info(f"Command {command} run as {username} by {client_ip}")
    print(f"[c] Command {command} run as {username} by {client_ip}")

def log_message(message):
    logging.info(message)
    print(f"[m] {message}")

def notify_discord(username, password, client_ip):
    data = {
        "content": f" SSH Honeypot: `{username}` logged in from `{client_ip}` with password `{password}`"
    }
    try:
        requests.post(DISCORD_WEBHOOK, json=data)
    except Exception as e:
        print(f"[!] Failed to send discord webhook: {e}")

class Timer:
    """Helper class to handling timing"""
    def __init__(self):
        self.start_time = time.time()
        self.last_time = self.start_time

    def checkpoint(self, label):
        now = time.time()
        delta = now - self.last_time
        total = now - self.start_time
        log_message(f"(Time) {label}: +{delta:.3f}s (Total: {total:.3f}s)")
        self.last_time = now

class HoneypotHandler(paramiko.ServerInterface):
    """Handler subclass for the honeypot server."""
    def __init__(self, client_ip, timer=None):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.timer = timer

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if self.timer:
            self.timer.checkpoint(f"[T] Password submitted for {username}")

        log_attempt(self.client_ip, username, password)
        if username in FAKE_CREDENTIALS and FAKE_CREDENTIALS[username] == password:
            log_success(self.client_ip, username, password)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        key_type = key.get_name()
        key_bits = key.get_bits()
        key_fingerprint = key.get_fingerprint().hex()
        key_base64 = key.get_base64()
        log_message(f"(pubkey) Public key attempt from {self.client_ip}")

        with open("publickeys.log", "a") as publog:
            publog.write(f"{self.client_ip} - {username}\n\tFingerprint: {key_fingerprint}\n\tType: {key_type}, Bits: {key_bits}\n\tKey: {key_base64}\n\n")
        log_attempt(self.client_ip, username, f"pubkey: {key.get_base64()[:20]}...")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        log_message(f"(Auth) Offering auth methods to {username}: publickey,password")
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
        return "logout\r\n", True
    elif command == "clear":
        return "\x1b[2J\x1b[H", False
    elif command == "whoami":
        return f"{user}\r\n", False
    elif command == "id":
        return f"uid=1000({user}) gid=1000({user}) groups=1000({user})\r\n", False
    elif command == "uname":
        return "Linux dguyserv 5.10.0-25-amd64 x86_64 GNU/Linux\r\n", False
    elif command.startswith("cd"):
        return "\r\n", False
    elif command.startswith("ls"):
        if "-la" in command or "-al" in command:
            return "drwxr-xr-x  2 dguy dguy 4096 Apr  1 17:00 .\r\n" + \
                   "drwxr-xr-x 15 root root 4096 Apr  1 17:00 ..\r\n" + \
                   "-rw-r--r--  1 dguy dguy   23 Apr  1 18:01 README.md\r\n" + \
                   "-rw-r--r--  1 dguy dguy   42 Apr  1 18:02 passwords.txt\r\n", False
        elif "-a" in command:
            return ".  ..  dguy.png  README.md  temp.txt  passwords.txt\r\n", False
        elif "-l" in command:
            return "-rw-r--r--  1 dguy dguy   23 Apr  1 18:01 README.md\r\n" + \
                   "-rw-r--r--  1 dguy dguy   42 Apr  1 18:02 passwords.txt\r\n", False
        return "dguy.png  README.md  temp.txt  passwords.txt\r\n", False
    elif command.startswith("man"):
        return "I hope you know what you're doing if you made it this far...\r\n", False
    elif command.startswith("cat"):
        fake_files = {
            "README.md": "# Welcome!\r\nYou successfully cat the readme file. Have fun looking around!\r\n",
            "passwords.txt": "dguy:dguh\r\nadmin:password123\r\nroot:fullpower\r\n",
            "temp.txt": "This is a temp file!\r\n"
        }
        parts = command.split()
        if len(parts) > 1 and parts[1] in fake_files:
            return fake_files[parts[1]], False
        return f"cat: {parts[1] if len(parts) > 1 else ''}: No such file or directory\r\n", False
    elif command.startswith("su"):
        time.sleep(2)
        return "su: Authentication failure\r\n", False
    else:
        return f"-bash: {command}: command not found\r\n", False

def handle_fake_shell(chan, user):
    """Let the trolling begin"""
    buffer = ""
    cursor_pos = 0
    history = []
    history_index = -1
    escape_seq = False
    escape_buffer = ""
    start_time = time.time()
    command_count = 0
    MAX_DURATION = 60
    MAX_COMMANDS = 20

    SHELL_STRING = f"{GREEN}{user}@dguyserv{RESET}:{BLUE}~{RESET}$ "
    chan.send("Welcome to Debian GNU/Linux 11\n\r")
    chan.send(SHELL_STRING)

    try:
        while True:
            if time.time() - start_time > MAX_DURATION:
                chan.send("\r\nYour free trial of bash has expired.\r\n")
                return
            if command_count >= MAX_COMMANDS:
                chan.send("\r\nYour free trial of bash has expired.\r\n")
                return

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
                                cursor_pos = len(buffer)
                                chan.send(f"\r\x1b[2K{SHELL_STRING}{buffer}")
                        elif escape_buffer == "[B": # Down
                            if history:
                                history_index = min(len(history), history_index + 1)
                                buffer = history[history_index] if history_index < len(history) else ""
                                cursor_pos = len(buffer)
                                chan.send(f"\r\x1b[2K{SHELL_STRING}{buffer}")
                        elif escape_buffer == "[C": # Right
                            if cursor_pos < len(buffer):
                                chan.send("\x1b[C")
                                cursor_pos += 1
                        elif escape_buffer == "[D": # Left
                            if cursor_pos > 0:
                                chan.send("\x1b[D")
                                cursor_pos -= 1
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
                elif byte == 12: # Ctrl-L
                    chan.send("\x1b[2J\x1b[H") # Clear screen and reset cursor
                    chan.send(SHELL_STRING + buffer)
                    continue
                elif byte in (10, 13): # Enter
                    chan.send("\r\n")
                    log_command(chan.origin_addr, user, buffer.strip())
                    output, should_exit = handle_fake_command(buffer, user)
                    chan.send(output)
                    if buffer.strip():
                        history.append(buffer)
                        command_count += 1
                    history_index = len(history)
                    if should_exit:
                        chan.send("logout\r\n")
                        return
                    buffer = ""
                    cursor_pos = 0
                    chan.send(SHELL_STRING)
                elif byte in (127, 8): # Backspace
                    if cursor_pos > 0:
                        buffer = buffer[:cursor_pos - 1] + buffer[cursor_pos:]
                        cursor_pos -= 1
                        chan.send("\b")
                        chan.send(buffer[cursor_pos:] + " ")
                        chan.send("\b" * (len(buffer) - cursor_pos + 1))
                elif byte == 126: # DEL
                    if cursor_pos < len(buffer):
                        buffer = buffer[:cursor_pos] + buffer[cursor_pos + 1:]
                        chan.send(buffer[cursor_pos:] + " ")
                        chan.send("\b" * (len(buffer) - cursor_pos + 1))
                elif 32 <= byte <= 126: # Printable chars
                    buffer = buffer[:cursor_pos] + char + buffer[cursor_pos:]
                    cursor_pos += 1
                    # Print inserted char, move cursor back
                    chan.send(buffer[cursor_pos - 1:])
                    chan.send("\b" * (len(buffer) - cursor_pos))

    except Exception as e:
        print(f"[!!] Exception in fake shell: {e}")
    finally:
        chan.close()

def handle_client(client_socket, client_ip):
    if client_ip in BANNED_IPS:
        log_banned_attempt(client_ip)
        reset_connection(client_socket)
        return

    log_connection_ip(client_ip)
    timer = Timer()
    try:
        timer.checkpoint("Connection accepted")

        transport = HoneypotTransport(client_socket)
        transport.local_version = CUSTOM_BANNER

        timer.checkpoint("Transport created and banner set")

        transport.add_server_key(HOST_KEY)
        server = HoneypotHandler(client_ip, timer)

        transport.start_server(server=server)
        timer.checkpoint("Start server completed")

        chan = transport.accept(120)
        timer.checkpoint("Channel accepted")

        if chan is None:
            raise Exception("No channel")

        if not transport.is_authenticated():
            raise Exception("Transport inactive before authentication")

        chan.origin_addr = client_ip
        username = transport.get_username()
        timer.checkpoint(f"Authenticated as {username}")

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

    try:
        while True:
            try:
                client_socket, addr = server_socket.accept()
                print(f"[+] Connection from {addr[0]}:{addr[1]}")
                threading.Thread(target=handle_client, args=(client_socket, addr[0])).start()
            except OSError:
                break
    except Exception as e:
        print(f"[!] Unhandled exception in main loop: {e}")

    finally:
        server_socket.close()
        print("[*] Server socket closed.")

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

if __name__ == "__main__":
    start_honeypot()
