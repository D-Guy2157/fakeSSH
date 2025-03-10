# main.py
# driver for the fake ssh / honeypot
import socket
import threading
import logging

# Configure Logging
logging.basicConfig(filename="honeypot.log", level=logging.INFO, format="%(asctime)s - %(messgae)s")

# Client Handling
def handle_client(client_socket, addr):
    pass

# Honeypot
def start_honeypot(host="0.0.0.0", port=22):
    pass

if __name__ == "__main__":
    start_honeypot()
