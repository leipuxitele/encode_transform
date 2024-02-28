import socket
import threading
import queue
import json
from time import sleep
import RSA

with open("server_file\\key.json", "r") as f:
    CA_key = json.load(f)

with open('setting.json', 'r') as f2:
    users = json.load(f2)

IP = users['IP']
PORT = users['port']

ADDRESS = {}  # 存储用户地址
Flag = 1  # 用于标记用户

# 双队列用于转发消息
messageA_queue = queue.Queue(maxsize=100)
messageB_queue = queue.Queue(maxsize=101)
lockA = threading.Lock()
lockB = threading.Lock()


def handle_client(conn: socket.socket, addr):
    """
    用户请求处理函数
    conn: 与用户的连接
    addr: 用户地址
    """
    global Flag, users, ADDRESS, CA_key
    cmd = conn.recv(1024).decode()

    if cmd == "Authentication Request":
        conn.send(b"OK")
        au_request = conn.recv(1024).decode()
        au_request = json.loads(au_request)
        user = au_request["user"]
        key = au_request["key"]
        if user in users and users[user] == key:
            if user in ADDRESS.keys():
                conn.send("User has been online".encode())
                conn.close()
                return
            ADDRESS[user] = addr
            conn.send("Authentication Success".encode())
        else:
            conn.send("Authentication Fail".encode())
            conn.close()
    else:
        conn.close()
        return

    next_cmd = conn.recv(1024).decode()
    if next_cmd == "Certificate Request":
        bind_request = conn.recv(1024)
        enp = RSA.encrypt(bind_request, CA_key["private_key"])
        conn.send(enp.encode())
    else:
        conn.close()
        return

    next_cmd = conn.recv(1024).decode()
    if next_cmd == "Communication Request":
        while True:
            thread_count = threading.active_count()
            if thread_count == 3 or thread_count == 4:
                info = {"info": "Communication Success", "flag": Flag}
                cu_flag = Flag
                Flag += 1
                conn.send(json.dumps(info).encode())
                break
            elif thread_count == 2:
                info = {"info": "Only one user online, please wait", "flag": 0}
                conn.send(json.dumps(info).encode())
                sleep(3)
            else:
                info = {"info": "Chat Room is full,Communication Fail", "flag": -1}
                conn.send(json.dumps(info).encode())
                conn.close()
    else:
        conn.close()
        return

    next_cmd = conn.recv(1024).decode()
    if next_cmd == "Connection Request":
        uu = ADDRESS.keys()
        other_user = ""
        for i in uu:
            if i != user:
                other_user = i
                break
        other_address = ADDRESS[other_user]
        conn.send(json.dumps({"user": other_user, "address": other_address}).encode())
        print("Connection Success")
    # 完成用户身份验证,密钥交换,通信建立,开始转发消息
    message_forwarding(user, conn, cu_flag)
    return


def message_forwarding(user, conn: socket.socket, Flag):

    global messageA_queue, messageB_queue, lockA, lockB

    def receive(conn: socket.socket, message: queue.Queue, lock: threading.Lock):
        """
        接收消息函数
        message: 消息队列
        lock: 锁
        """
        while True:
            try:
                mes = conn.recv(2048)
                lock.acquire()
                message.put(mes)
                lock.release()
            except BaseException:
                print(f"Connection from {user} has been interrupted")
                exit(0)

    def send(conn: socket.socket, message: queue.Queue, lock: threading.Lock):
        """
        发送消息函数
        message: 消息队列
        lock: 锁
        """
        while True:
            if not message.empty():
                lock.acquire()
                mes = message.get()
                lock.release()
                conn.send(mes)
    try:
        # 对于不同的用户连接线程,接收和发送消息的队列嵌套使用,双队列四线程保证消息的顺序转发
        if (Flag == 1):
            send_thread = threading.Thread(target=send, args=(conn, messageA_queue, lockA))
            send_thread.setName("send_thread_A")
            receive_thread = threading.Thread(target=receive, args=(conn, messageB_queue, lockB))
            receive_thread.setName("receive_thread_B")
            receive_thread.start()
            send_thread.start()
        else:
            send_thread = threading.Thread(target=send, args=(conn, messageB_queue, lockB))
            send_thread.setName("send_thread_B")
            receive_thread = threading.Thread(target=receive, args=(conn, messageA_queue, lockA))
            receive_thread.setName("receive_thread_A")
            receive_thread.start()
            send_thread.start()
    except BaseException:
        print("Connection interrupted")
        exit(0)


def main():
    global IP, PORT, ADDRESS
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.bind((IP, PORT))
    conn.listen(5)
    while True:
        s_conn, s_addr = conn.accept()
        print(f"Connection from {s_addr} has been established!")
        client_thread = threading.Thread(target=handle_client, args=(s_conn, s_addr))
        client_thread.start()


main()
