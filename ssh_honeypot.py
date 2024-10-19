# Labraries
import logging
from logging.handlers import RotatingFileHandler
import socket
import requests # type: ignore
import paramiko # type: ignore
import threading
import re

# Constants
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

host_key = paramiko.RSAKey(filename='server.key')

#loggers & logging files
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)

# funnel_handler provide some format for funnel_logger
funnel_handler = RotatingFileHandler('attaker_info.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)

# audits.log --> log attaker info ip address/ passwords...
funnel_logger.addHandler(funnel_handler)

# the info in session will be document in another log file --> cmd_audits.log
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('sessions_info.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)



# Emulated Shell
def emulated_shell(channel, client_ip,timeout_event):
    prompt = b'root@server:~# '  # Default prompt
    channel.send(prompt)  # Send the initial prompt
    command = b""
    
    while True:
        char = channel.recv(1)  # Read input character-by-character
        channel.send(char)  # Echo back the character to the client

        if not char:
            channel.close()
            return
        
        # Detect backspace (usually '\x7f')
        if char == b'\x08' or char == b'\x7f':  # Backspace or Delete
            if len(command) > 0:
                # Remove last character from command
                command = command[:-1]
                # Move cursor back, clear character, move cursor back again
                channel.send(b'\x08 \x08')  
            continue  # Skip further processing for backspace

        timeout_event.set()

        command += char


        # command handler
        if char == b'\r':  # When Enter key is pressed

            command = command.strip()

            if command == b'exit':
                response = b'\r\nGoodbye!\r\n'
                channel.send(response)
                channel.close()
                return
            
            elif command == b'':  # Empty command (just Enter pressed)
                response = b'\r\n'

            else:
                url = "http://127.0.0.1:12345/execute"
                params = {"command": command}
                response_text = requests.get(url, params=params).text.strip()

                if not response_text:
                    response_text = "bash: {}: command not found.".format(command.decode())

                response = format_for_terminal(response_text).encode('utf-8')

            # Ensure proper newlines before the response
            channel.send(b'\r\n' + response + b'\r\n')  # Send the response
            channel.send(prompt)  # Send the prompt for the next command
            command = b""

    channel.close()

def format_for_terminal(response_text):
    """
    Function to format the response text with proper spacing and newlines
    for terminal output. Adjusts tab spaces, line breaks, etc.
    """

    # Step 1: Replace tabs with spaces for proper alignment
    response_text = response_text.replace("\t", "    ")

    # Step 2: Remove 'plaintext' markers and any dots (...)
    # Using regex to remove unwanted artifacts like 'plaintext' and '...'
    response_text = re.sub(r'\bplaintext\b', '', response_text)  # Remove 'plaintext'
    response_text = re.sub(r'\.{2,}', '', response_text)  # Remove multiple dots (e.g., '...')
    # Remove backticks (```)
    response_text = re.sub(r'[`]', '', response_text)  # Remove backticks

    # Step 3: Ensure proper newline endings consistent with terminal output
    response_text = response_text.replace("\n", "\r\n")

    return response_text



# SSH Server + Sockets

class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        
    def get_allowed_auth(self):
        return "password"
    
    def check_auth_password(self, username, password):
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password :
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL    

        
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height,pixelwidth,pixelheight, modes):
        return True
    
    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True
    
def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the SSH server.")

    timeout_event = threading.Event()

    def timeout_handler():
        if client and not client._closed:  # Check if the client is still open
            print(f"Connection to {client_ip} timed out.")
            client.close()

    timer = threading.Timer(100.0, timeout_handler)
    try:
        
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username= username, input_password=password)

        transport.add_server_key(host_key)

        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")
            return

        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"
        channel.send(standard_banner)

        timer.start()  # Start the timeout timer
        emulated_shell(channel, client_ip=client_ip, timeout_event=timeout_event)


    except Exception as error:
        print(error)
        print("!!!Error!!!")
    finally:
        try:
            timer.cancel() 
            transport.close()
        except Exception as error:
            print(error)
            print("!!!Error!!!")
        client.close()


# Provision SSH-based Honeypot

def honeypot(address, port, username, password):

    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    socks.bind((address,port))

    socks.listen(100)
    print(f"SSH server is listening on port {port}")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle,args=(client,addr,username,password))
            ssh_honeypot_thread.start()
        except Exception as error:
            print(error)


honeypot('127.0.0.1', 2222, username= 'root', password=None)