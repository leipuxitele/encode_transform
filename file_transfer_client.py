import json
import tkinter
from tkinter.scrolledtext import ScrolledText
import socket
from file_transfer import file_transfer
from AES_ECB import AES_ECB
import RSA
from RC4 import RC4

Command = ""  # 要执行的命令
file_save_path = "client_file\\"
cmd = ""
with open("client_file\\root.json", "r") as f:
    p = json.load(f)
server_pk = p["public_key"]
seed = "abcdef1234567890"

# 总体框架
root1 = tkinter.Tk()
root1.geometry("500x400")
root1.title("文件传输助手")
root1.resizable(False, False)

# 文件路径
FILENAME0 = tkinter.StringVar()
FILENAME0.set("")

labelFILENAME0 = tkinter.Label(root1, text="文件地址", bg="white")
labelFILENAME0.place(x=220, y=100, width=100, height=30)
entryFILENAME0 = tkinter.Entry(root1, width=60, textvariable=FILENAME0)
entryFILENAME0.place(x=320, y=100, width=150, height=30)


# 文件列表页面
listbox = ScrolledText(root1)
listbox.place(x=0, y=0, width=225, height=400)
listbox.tag_config("tag1", foreground="blue", background="red")
listbox.insert(tkinter.END, "<---------文件列表--------->", "tag1")

# 连接服务器2
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1"
port = 9998
client.connect((host, port))
print("连接成功")
aes = AES_ECB(128)
rc4 = RC4(seed.encode())
key = {"aes_key": str(aes.key), "rc4_key": seed}
key = json.dumps(key)
key_data = RSA.encrypt(key.encode(), server_pk)
client.sendall(key_data.encode())

T = file_transfer(client, (host, port), aes, rc4)
Filename = entryFILENAME0.get()


def mget():
    Fileroad = entryFILENAME0.get()
    cmd = "get"
    client.sendall(cmd.encode("utf-8"))
    file_name = Fileroad
    save_path = file_save_path
    T.client_get(file_name, save_path)


def mput():
    Fileroad = entryFILENAME0.get()
    cmd = "put"
    client.sendall(cmd.encode("utf-8"))
    file_name = file_save_path + Fileroad
    T.client_put(file_name)


def mls():
    cmd = "ls"
    client.sendall(cmd.encode("utf-8"))
    a = client.recv(10000)
    a = aes.decrypt(a)
    a = a.decode()
    a = a.split(" ")
    listbox.delete("1.0", tkinter.END)
    for x in a:
        listbox.insert(tkinter.END, x)


# 各种按钮
loginButton = tkinter.Button(root1, text="文件刷新", command=mls, bg="white")
loginButton.place(x=300, y=240, width=80, height=25)
root1.bind("<Return>", "mls")

loginButton = tkinter.Button(root1, text="文件下载", command=mget, bg="white")
loginButton.place(x=300, y=320, width=80, height=25)
root1.bind("<Return>", "mget")

loginButton = tkinter.Button(root1, text="文件上传", command=mput, bg="white")
loginButton.place(x=300, y=280, width=80, height=25)
root1.bind("<Return>", "mput")


root1.mainloop()
