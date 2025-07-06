import socket

BT_ADDRESS = "08:9d:f4:c2:d3:fe"

client = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)

client.connect((BT_ADDRESS, 4))


try:
    while True:
        message = input("Enter message: ")
        client.send(message.encode("UTF-8"))
        data = client.recv(1024)
        if not data:
            break
        print("Message: ", data.decode("UTF-8"))
except OSError as e:
    print(e)
    pass

client.close()