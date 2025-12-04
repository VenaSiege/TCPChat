import socket
import threading
import sys
from datetime import datetime

class ChatClient:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.username = None

    def connect(self):
        """连接到服务器"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.connected = True
            print(f"[客户端] 已连接到 {self.host}:{self.port}\n")
            return True
        except ConnectionRefusedError:
            print(f"[错误] 无法连接到服务器 {self.host}:{self.port}")
            print("[提示] 请确保服务器已启动")
            return False
        except Exception as e:
            print(f"[错误] 连接失败: {e}")
            return False

    def set_username(self):
        """设置用户名"""
        while not self.username:
            name = input("请输入你的用户名 (默认为 Guest): ").strip()
            self.username = name if name else "Guest"

        # 发送用户名到服务器
        self.socket.send(self.username.encode('utf-8'))

        # 接收欢迎消息
        try:
            welcome = self.socket.recv(1024).decode('utf-8')
            print(welcome)
        except:
            pass

    def receive_messages(self):
        """接收来自服务器的消息"""
        while self.connected:
            try:
                message = self.socket.recv(1024).decode('utf-8')
                if message:
                    print(f"\n{message}", end='')
                    print("> ", end='', flush=True)
                else:
                    self.connected = False
                    print("\n[系统] 已断开连接")
                    break
            except ConnectionResetError:
                self.connected = False
                print("\n[系统] 服务器已断开连接")
                break
            except Exception as e:
                if self.connected:
                    print(f"\n[错误] 接收消息失败: {e}")
                break

    def send_messages(self):
        """发送消息到服务器"""
        print("开始聊天 (输入 'exit' 退出):\n")
        print("> ", end='', flush=True)

        try:
            while self.connected:
                message = input().strip()

                if message.lower() == 'exit':
                    print("[客户端] 正在断开连接...")
                    self.connected = False
                    break

                if not message:
                    print("> ", end='', flush=True)
                    continue

                try:
                    self.socket.send(message.encode('utf-8'))
                    print("> ", end='', flush=True)
                except Exception as e:
                    print(f"\n[错误] 发送消息失败: {e}")
                    self.connected = False
                    break
        except KeyboardInterrupt:
            print("\n[客户端] 正在断开连接...")
            self.connected = False

    def run(self):
        """运行客户端"""
        if not self.connect():
            return

        self.set_username()

        # 创建接收消息的线程
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_thread.start()

        # 主线程处理发送消息
        self.send_messages()

        self.disconnect()

    def disconnect(self):
        """断开连接"""
        self.connected = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        print("[客户端] 已断开连接")

def main():
    print("=" * 50)
    print("         TCP 聊天客户端")
    print("=" * 50)

    host = input("请输入服务器地址 (默认为 localhost): ").strip()
    host = host if host else 'localhost'

    port_input = input("请输入服务器端口 (默认为 5000): ").strip()
    port = int(port_input) if port_input else 5000

    print()

    client = ChatClient(host=host, port=port)
    client.run()

if __name__ == '__main__':
    main()
