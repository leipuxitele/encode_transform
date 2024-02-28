"""
    文件传输模块
    主要功能:
        1. 客户端上传文件
        2. 客户端下载文件
"""

import socket
import hashlib
import os
import json
import struct
import time
from AES_ECB import AES_ECB
from RC4 import RC4


def calculate_sha256(file_path):
    """
    SHA-256hash计算
    目的: 用于校验文件完整性
    """

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def record_log(log: str, addr: tuple):
    """
    日志记录
    目的: 记录文件传输过程中的服务端信息,客户端信息直接打印
    """

    with open("server_file\\log.txt", "a", encoding="utf-8") as file:
        file.write(addr[0] + str(addr[1]) + log + " ")
        current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        file.write(f"{current_time}\n")


class file_transfer:
    """
    文件传输模块
    """

    def __init__(self, conn: socket.socket, addr: tuple, aes: AES_ECB, rc4: RC4):
        """
        conn: socket连接
        addr: 服务端/客户端地址(IP,PORT)
        """
        self.aes = aes
        self.rc4 = rc4
        self.conn = conn
        self.addr = addr

    def client_put(self, file_path):
        """
        客户端上传文件方法,与server_rec配合使用
        file_path: 客户端所传文件路径
        """
        file_name = file_path.split("\\")[-1]
        file_sha_256 = calculate_sha256(file_path)
        file_size = str(os.path.getsize(file_path))

        data_hear = {"filename": file_name, "filesize": file_size, "filesha256": file_sha_256}
        length_header = len(json.dumps(data_hear))

        self.conn.sendall(struct.pack("i", length_header))
        header_data = self.aes.encrypt(json.dumps(data_hear).encode("utf-8"))
        self.conn.sendall(header_data)
        up_start_re = self.conn.recv(1024)
        if up_start_re.decode("utf-8") == "OK":
            with open(file_path, "rb") as file:
                for line in file:
                    line = self.rc4.stream_encrypt(line)
                    self.conn.sendall(line)
            print("上传成功")
        else:
            print("服务器拒绝,上传失败")

    def client_get(self, file_name, save_path):
        """
        客户端下载文件方法,与server_send配合使用
        save_path: 客户端保存文件路径
        file_name: 客户端所要下载文件名
        """
        file_name = self.aes.encrypt(file_name.encode("utf-8"))
        self.conn.sendall(file_name)  # 发送文件名请求文件
        print("正在下载...")
        response_header = self.conn.recv(4)
        if not response_header:
            print("服务器断开连接")
            return
        response_header = struct.unpack("i", response_header)[0]  # 得到报文头信息长度
        if response_header == 0:
            print(self.conn.recv(1024).decode("utf-8"))  # 文件不存在,打印错误信息
            return

        # 接收文件报文头
        data_length = 0
        data = b""
        while data_length < response_header:
            data += self.conn.recv(1024)
            data_length = len(data)
        data = self.aes.decrypt(data)
        data = data.decode("utf-8")
        data = json.loads(data)
        filename = data["filename"]
        filesize = int(data["filesize"])
        filesha256 = data["filesha256"]

        # 接收文件
        with open(save_path + data["filename"], "wb") as file:
            data_length = 0
            file_sha256 = hashlib.sha256()
            while data_length < filesize:
                data = self.conn.recv(1024)
                data = self.rc4.stream_encrypt(data)
                file_sha256.update(data)
                data_length += len(data)
                file.write(data)
        if file_sha256.hexdigest() == filesha256:  # 校验哈希
            print("文件下载完成")
        else:
            print("文件下载失败,数据出现错误")
            os.remove(save_path + filename)

    def server_send(self, file_save_path):
        """
        服务器发送文件方法,与client_get配合使用
        file_save_path: 服务器所发文件路径
        """

        request_header = self.conn.recv(1024)  # 接收
        request_header = self.aes.decrypt(request_header)
        filename = request_header.decode("utf-8")
        if os.path.exists(file_save_path + filename):
            filesize = os.path.getsize(file_save_path + filename)
            filesha256 = calculate_sha256(file_save_path + filename)
            data_header = {"filename": filename, "filesize": filesize, "filesha256": filesha256}
            length_header = len(json.dumps(data_header))
            self.conn.sendall(struct.pack("i", length_header))
            data_header = json.dumps(data_header)
            data_header = self.aes.encrypt(data_header.encode("utf-8"))
            self.conn.sendall(data_header)
            time.sleep(0.1)
            with open(file_save_path + filename, "rb") as file:
                for line in file:
                    line = self.rc4.stream_encrypt(line)
                    self.conn.sendall(line)
            record_log(filename + " " + "下载成功", self.addr)
        else:
            self.conn.sendall(struct.pack("i", 0))
            self.conn.sendall("文件不存在".encode("utf-8"))
            record_log(filename + " " + "下载失败", self.addr)

    def server_rec(self, file_save_path: str):
        """
        服务器接收文件方法,与client_put配合使用
        file_save_path: 服务器保存文件路径
        """

        request_header = self.conn.recv(4)
        request_header = struct.unpack("i", request_header)[0]
        if request_header == 0:
            self.conn.sendall("文件不存在".encode("utf-8"))
            record_log("客户端上传失败", self.addr)
            return
        data_length = 0
        data = b""
        while data_length < request_header:
            data += self.conn.recv(1024)
            data_length = len(data)
        data = self.aes.decrypt(data)
        data = data.decode("utf-8")
        data = json.loads(data)
        filename = data["filename"]
        filesize = int(data["filesize"])
        filesha256 = data["filesha256"]
        if filesize < 1024 * 1024 * 1024:
            self.conn.sendall("OK".encode("utf-8"))
            with open(file_save_path + data["filename"], "wb") as file:
                data_length = 0
                file_sha256 = hashlib.sha256()
                while data_length < filesize:
                    data = self.conn.recv(1024)
                    data = self.rc4.stream_encrypt(data)
                    file_sha256.update(data)
                    data_length += len(data)
                    file.write(data)
            if file_sha256.hexdigest() == filesha256:
                record_log(filename + " " + "文件接收完成", self.addr)
            else:
                record_log(filename + " " + "文件接收失败,数据出现错误", self.addr)
                os.remove(file_save_path + filename)
        else:
            self.conn.sendall("NO".encode("utf-8"))
            record_log("文件超过1G,拒绝接收", self.addr)

    def server_ls(self, file_save_path: str):
        """
        服务器返回文件列表
        """

        file_list = os.listdir(file_save_path)
        file_list = "\n".join(file_list)
        file_list = self.aes.encrypt(file_list.encode("utf-8"))
        self.conn.sendall(file_list)
