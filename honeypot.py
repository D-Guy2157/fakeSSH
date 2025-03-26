# honeypot.py
# driver for the fake ssh / honeypot
import logging
import os
import socket
import threading

import paramiko # (I'm not cracked enough to make my own SSH implementation... yet)

# Fake host key
HOST_KEY_FILE = "host_key.pem"

# Basic Logging
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
    logging.info(f"Connection from {client_ip}, User: {username}, Pass: {password}")
    print(f"[i] Logged attempt from {client_ip} with {username}:{password}")

# Handler
class HoneypotHandler(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_attempt(self.client_ip, username, password)
        return paramiko.AUTH_FAILED # Always fail auth

def handle_client(client_socket, client_ip):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)
    server = HoneypotHandler(client_ip)

    try:
        transport.start_server(server=server)
        chan = transport.accept(120)
        if chan is None:
            raise Exception("No channel")
    except Exception as e:
        print(f"[!] Exception: {e}")
    finally:
        transport.close()

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
