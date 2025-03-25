# main.py
# driver for the fake ssh / honeypot
import socket
import threading
import logging

# Configure Logging
logging.basicConfig(filename="honeypot.log", level=logging.INFO, format="%(asctime)s - %(messgae)s")

# Client Handling
def handle_client(client_socket, addr):
    logging.info(f"Connection from {addr}")

    # Fake Banner
    client_socket.sendall(b"SSH-2.0-OpenSSH_9.9p2 Debian-1\n")

    # Receive creds
    try:
        data = client_socket.recv(1024).decode("utf8").strip()
        logging.info(f"Attempted login from {addr}: {data}")
    except Exception as e:
        logging.error(f"Error reciving data from {addr}: {e}")

    client_socket.close()


# Honeypot
def start_honeypot(host="0.0.0.0", port=22):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    logging.info(f"SSH Honeypot listening on {host}: {port}")

    while True:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

if __name__ == "__main__":
    start_honeypot()
