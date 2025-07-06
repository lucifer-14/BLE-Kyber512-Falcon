import socket

BT_ADDRESS = "08:9d:f4:c2:d3:fe"


server = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)

server.bind((BT_ADDRESS, 4))
print('ok1')
server.listen(1)
print('ok2')

conn, addr = server.accept()

try:
    while True:
        data = conn.recv(1024)
        if not data:
            break
        else:
            print("Message: ", data.decode('UTF-8'))
            message = input("Enter message: ")
            conn.send(message.encode('UTF-8'))
except OSError as e:
    print(e)
    pass

conn.close()
server.close()
