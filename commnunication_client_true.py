import random
import socket
import tkinter
import tkinter.messagebox
import threading
import json
import tkinter.filedialog
from tkinter.scrolledtext import ScrolledText
import RSA
import time
import os
import hashlib
from AES_ECB import AES_ECB
from tkinter.scrolledtext import  ScrolledText
from PIL import Image, ImageTk,ImageDraw

IP = ""
PORT = ""

user = ""
Key = ""

listbox1 = ""  # 用于显示在线用户的列表框
show = 1  # 用于判断是开还是关闭列表框
others_p = ()  # 用于存储对方的公钥
certification = b""  # 数字证书
with open("client_file\\root.json", 'r') as f:
    c = json.load(f)
CA_root = c["public_key"]  # 加密CA公钥
aes = None


def Login():
    """
    登录函数
    获取IP地址、端口号、用户名、密码
    """
    global IP, PORT, user, Key
    IP, PORT = entryIP.get().split(":")
    user = entryUSER.get()
    Key = entryKEY.get()
    if not user:
        tkinter.messagebox.showwarning("warning", message="用户名为空!")
    else:
        root0.destroy()


def openF():
    """
    打开文件传输窗口
    """
    t_f = os.popen("python file_transfer_client.py")
    print(t_f.read())


def exchange_key_request(conn: socket.socket):
    """
    密钥交换请求
    conn: 与服务器的连接
    """
    global others_p, CA_root, other_user, aes
    # aes_key = [random.randint(0, 255) for i in range(16)]
    aes_key = [i for i in range(16)]  # 生成AES密钥
    aes = AES_ECB(128, aes_key)

    s.send(b"Exchange Key Request")
    temp_res = s.recv(1024).decode()
    if temp_res == "OK":
        print("Start exchange key")
        s.send(certification)  # 验证数字证书
        recv = conn.recv(4096)
        ver = RSA.decrypt(recv.decode(), CA_root)
        try:
            ver = ver.decode()
            ver = json.loads(ver)
            if other_user != ver["user"]:
                raise BaseException
        except BaseException:
            print("Verification Fail")
            exit(0)
        others_p = ver["public_key"]
        print("Verification Success")

        aes_data = str(aes_key)  # 交换AES密钥
        hash_data = hashlib.sha1(aes_data.encode()).hexdigest()
        ex_data = {"aes_key": aes_data, "hash": hash_data}
        ex_data = json.dumps(ex_data)
        ex_data = RSA.encrypt(ex_data.encode(), others_p)
        conn.send(ex_data.encode())
        recv = conn.recv(1024).decode()
        print("request exchange_result", recv)
    else:
        print("request exchange key fail")
        exit(0)


def exchange_key_response(conn: socket.socket):
    """
    密钥交换响应
    conn: 与服务器的连接
    """
    global others_p, CA_root, other_user, aes
    re = conn.recv(1024).decode()
    if re == "Exchange Key Request":
        conn.send(b"OK")
        print("Start exchange key")
        recv_data = conn.recv(4096)
        ver = RSA.decrypt(recv_data.decode(), CA_root)  # 验证数字证书
        try:
            ver = ver.decode()
            ver = json.loads(ver)
            if other_user != ver["user"]:
                raise BaseException
        except BaseException:
            print("Verification Fail")
            exit(0)
        others_p = ver["public_key"]
        print("Verification Success")
        conn.send(certification)

        aes_data = conn.recv(4096).decode()  # 交换AES密钥
        aes_data = my_rsa.decrypt(aes_data)
        aes_data = json.loads(aes_data)
        if aes_data["hash"] != hashlib.sha1(aes_data["aes_key"].encode()).hexdigest():
            print("Verification Fail")
            exit(0)
        aes_key = aes_data["aes_key"]
        aes = AES_ECB(128, eval(aes_key))
        conn.send(b"Verification Success")
        print("response: verification success")


def creat_image(image_path):
    #image_path = 图片路径
    image = Image.open(image_path)
    image = image.resize((30, 35))
    mask = Image.new("L", image.size, 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0, image.size[0], image.size[1]), fill=255)
    result = Image.new("RGBA", image.size)
    result.paste(image, (0, 0), mask=mask)
    photo = ImageTk.PhotoImage(result)
    label = tkinter.Label(listbox, image=photo)
    label.image = photo
    return label

def send(listbox, conn: socket.socket):
    """
    发送消息函数
    listbox: 消息框
    conn: 与服务器的连接
    """
    global aes
    assert isinstance(aes, AES_ECB)
    message = entryIuput.get()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    listbox.tag_config("tag4", font=('Yu Gothic UI Semilight', 10))
    listbox.tag_config("tag5", font=('Times New Roman', 12))
    listbox.insert(tkinter.END, "\n")
    listbox.insert(tkinter.END, " " * 48 + timestamp + '\n', "tag4")
    listbox.window_create(tkinter.END, window=creat_image('pcs/3.png'))
    listbox.insert(tkinter.END, user + ":  ", "tag5")
    listbox.insert(tkinter.END, message + "\n", "tag4")

    salt = random.randint(0, 10 ** 20)  # 加盐值可以防止消息重放
    message = message + ";;;" + str(salt) + ";;;" + str(timestamp)
    enc = aes.encrypt(message.encode())
    conn.send(enc)
    INPUT.set("")


def receive(listbox, conn: socket.socket):
    """
    接收消息函数
    listbox: 消息框
    conn: 与服务器的连接
    """
    global aes, other_user
    assert isinstance(aes, AES_ECB)
    while True:
        data = conn.recv(4096)
        data = aes.decrypt(data).decode()
        data = data.split(";;;")
        message = data[0]
        timestamp = data[2]

        listbox.tag_config("tag4", font=('Yu Gothic UI Semilight', 10))
        listbox.tag_config("tag5", font=('Times New Roman', 12))
        listbox.insert(tkinter.END, "\n")
        listbox.insert(tkinter.END, " " * 48 + timestamp + '\n', "tag4")
        listbox.window_create(tkinter.END, window=creat_image('pcs/2.png'))
        listbox.insert(tkinter.END, other_user + ":  ", "tag5")
        listbox.insert(tkinter.END, message + "\n", "tag4")


# 登陆窗口
root0 = tkinter.Tk()
root0.geometry("300x200")
root0.title("用户登陆窗口")
root0.resizable(False, False)
one = tkinter.Label(root0, width=300, height=150, bg="LightBlue")
one.pack()

IP0 = tkinter.StringVar()
IP0.set("")
USER = tkinter.StringVar()
USER.set("")
KEY = tkinter.StringVar()
KEY.set("")

labelIP = tkinter.Label(root0, text="IP地址", bg="LightBlue")
labelIP.place(x=20, y=20, width=100, height=40)
entryIP = tkinter.Entry(root0, width=60, textvariable=IP0)
entryIP.place(x=120, y=25, width=100, height=30)

labelUSER = tkinter.Label(root0, text="用户名", bg="LightBlue")
labelUSER.place(x=20, y=70, width=100, height=40)
entryUSER = tkinter.Entry(root0, width=60, textvariable=USER)
entryUSER.place(x=120, y=75, width=100, height=30)

labelKEY = tkinter.Label(root0, text="密码", bg="LightBlue")
labelKEY.place(x=20, y=120, width=100, height=40)
entryKEY = tkinter.Entry(root0, width=60, textvariable=KEY)
entryKEY.place(x=120, y=120, width=100, height=30)

loginButton = tkinter.Button(root0, text="文件传输", command=openF, bg="Yellow")
loginButton.place(x=165, y=160, width=60, height=25)

FButton = tkinter.Button(root0, text="登录", command=Login, bg="Yellow")
FButton.place(x=110, y=160, width=40, height=25)
root0.bind("<Return>", 'Login')
root0.mainloop()

# 建立连接
my_rsa = RSA.RSA(1024)  # 生成自身RSA密钥对
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((IP, int(PORT)))

# 身份验证
Au_request = {"user": user, "key": Key}
s.send(b"Authentication Request")
mess = s.recv(1024)
if mess == b"OK":
    s.send(json.dumps(Au_request).encode())
else:
    print("Authentication Fail")
    exit(0)
au_result = s.recv(1024)
if au_result.decode() == "Authentication Success":
    print("Authentication Success")
else:
    print("Authentication Fail")
    exit(0)

# 请求数字证书
s.send(b"Certificate Request")
time.sleep(0.1)
bind_request = {"user": user, "public_key": my_rsa.public_key}
s.send(json.dumps(bind_request).encode())
certification = s.recv(4096)

# 请求建立通信
s.send(b"Communication Request")
while True:
    info = s.recv(1024).decode()
    info = json.loads(info)
    if info["info"] == "Communication Success":
        print("Connection Success")
    flag = info["flag"]  # flag用来标识聊天室是否已满,区分密钥交换的接收和发送方
    if flag > 0:
        s.send(b"Connection Request")
        temp_response = s.recv(1024).decode()
        temp_response = json.loads(temp_response)
        other_user = temp_response["user"]
        other_address = temp_response["address"]
        print("your chat user is", other_user, other_address)
        if flag == 1:
            exchange_key_request(s)
        if flag == 2:
            exchange_key_response(s)
        break
    elif flag == 0:
        print("please wait for other user's connection......")
    else:
        print("Chat Room is full,Communication Fail")
        exit(0)

# 聊天窗口
root1 = tkinter.Tk()
root1.geometry("640x480")
root1.title("群聊")
root1.resizable(False, False)

# 消息界面
listbox = ScrolledText(root1)
listbox.place(x=5, y=0, width=640, height=320)
listbox.tag_config("tag1", foreground="red", background="yellow", font=("华文仿宋", 15))
padding = " " * 22
listbox.insert(tkinter.END, padding + "欢迎进入群聊，大家开始聊天吧!" + padding, "tag1")

INPUT = tkinter.StringVar()
INPUT.set("")
entryIuput = tkinter.Entry(root1, width=120, textvariable=INPUT)
entryIuput.place(x=5, y=320, width=580, height=170)

# 在线用户列表
listbox1 = tkinter.Listbox(root1, font=('Times New Roman', 12))
listbox1.place(x=510, y=0, width=130, height=320)
listbox1.insert(tkinter.END, "    当前在线用户")
listbox1.insert(tkinter.END, "\n------Users List-----\n")
listbox1.insert(tkinter.END, user)
listbox1.insert(tkinter.END, other_user)
sendButton = tkinter.Button(root1, text="\n发\n\n\n送", anchor="n", command=lambda: send(listbox, s), font=("Helvetica", 18), bg="white")
sendButton.place(x=585, y=320, width=55, height=300)

r = threading.Thread(target=receive, args=(listbox, s))
r.start()  # 开始线程接收信息

root1.mainloop()
s.close()
