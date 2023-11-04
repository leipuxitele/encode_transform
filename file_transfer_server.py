import json
import threading
from AES_ECB import AES_ECB
import RSA
import file_transfer
import socket

IP = "127.0.0.1"
PORT = 9998
with open("server_file\\key.json", 'r') as f:
    p = json.load(f)
server_dk = p['private_key']
file_save_path = "server_file\\"
file_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
file_conn.bind((IP, PORT))
file_conn.listen(5)


def file_server():
    f_conn, f_addr = file_conn.accept()
    print(f"Connection from {f_addr} has been established!")

    # get key
    data = f_conn.recv(2048).decode()
    aes_data = RSA.decrypt(data, server_dk)
    aes_key = eval(aes_data.decode())
    aes = AES_ECB(128, aes_key)
    T = file_transfer.file_transfer(f_conn, f_addr, aes=aes)
    while True:
        cmd = f_conn.recv(1024).decode()
        if cmd == "get":
            T.server_send(file_save_path)
        elif cmd == "put":
            T.server_rec(file_save_path)
        elif cmd == "ls":
            T.server_ls(file_save_path)
        else:
            print("Wrong command!")


if __name__ == "__main__":
    thread1 = threading.Thread(target=file_server)
    thread1.start()
    thread2 = threading.Thread(target=file_server)
    thread2.start()
    thread1.join()
    thread2.join()
