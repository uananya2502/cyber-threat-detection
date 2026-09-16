import socket

HOST = "0.0.0.0"
PORT = 2222

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

print("Honeypot started")
print("Listening on port", PORT)

while True:
    client, address = server.accept()
    print("Connection received from:", address)
    client.send(b"SSH-2.0-OpenSSH_8.2p1\r\n")
    client.close()
