# main.py
# driver for the fake ssh / honeypot
import socket
import threading
import logging
import argparse

# Configure Logging
logging.basicConfig(filename="honeypot.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Silent mode flag
silent_mode = False

# Output
def log_message(level, message):
    if not silent_mode:
        print(message)
    if level == "info":
        logging.info(message)
    elif level == "error":
        logging.error(message)

# Client Handling
def handle_client(client_socket, addr):
    log_message("info", f"Connection from {addr}")

    # Fake Banner
    client_socket.sendall(b"SSH-2.0-OpenSSH_9.9p2 Debian-1\n")

    # Receive creds
    try:
        data = client_socket.recv(1024).decode("utf8").strip()
        log_message("info", f"Attempted login from {addr}: {data}")
    except Exception as e:
        log_message("error", f"Error reciving data from {addr}: {e}")

    client_socket.close()


# Honeypot
def start_honeypot(host="0.0.0.0", port=2222):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    log_message("info", f"SSH Honeypot listening on {host}:{port}")

    while True:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH Honeypot")
    parser.add_argument("--silent", action="store_true", help="Suppress console output")
    args = parser.parse_args()

    silent_mode = args.silent
    
    start_honeypot()
