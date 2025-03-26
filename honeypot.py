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

    def get_allowed_auths(self, username):
            return "password"

    def start_fake_shell(self, chan, user):
        """Let the trolling begin"""
        # TODO: Fix SSH client errors (make shell interactive?)
        # TODO: Add disconnect timeout
        try:
            chan.send("\nWelcome to Debian GNU/Linux 11\n")
            count = 0
            while count < 21:
                chan.send(f"{user}@dguyserv:~$")
                command = chan.recv(1024).decode().strip()
                count += 1
                if not command:
                    break

                if command in ["exit", "logout"]:
                    chan.send("logout\n")
                    break
                elif command in ["whoami"]:
                    chan.send(f"{user}\n")
                elif command.startswith("cd"):
                    chan.send("\n")
                elif command.startswith("ls"):
                    chan.send("dguy.png  README.md  temp.txt  passwords.txt\n")
                elif command.startswith("su"):
                    time.sleep(2)
                    chan.send("su: Authentication failure")
                else:
                    chan.send(f"-bash: {command}: command not found\n")

        except Exception as e:
            print(f"[!!] Exception in fake shell: {e}")
        finally:
            # TODO: Block IP
            chan.close()

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
            server.start_fake_shell(chan, username)
    except Exception as e:
        print(f"[!] Exception for {client_ip}: {e}")
    finally:
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
