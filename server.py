import socket
import threading
import time
from datetime import datetime
from auth_manager import AuthenticationManager

class ChatServer:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = []
        self.lock = threading.Lock()
        self.running = True
        self.auth_manager = AuthenticationManager()

    def start(self):
        """启动服务器"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        print(f"[服务器] 启动成功，监听 {self.host}:{self.port}")
        print(f"[服务器] 等待客户端连接...\n")

        try:
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        print(f"[错误] 接收连接时出错: {e}")
        except KeyboardInterrupt:
            print("\n[服务器] 正在关闭...")
        finally:
            self.shutdown()

    def handle_authentication(self, client_socket):
        """
        处理认证协议

        Args:
            client_socket: 客

        Returns:
            (authenticated: bool, username: str) 元组
        """
        try:
            while True:
                # 接收认证命令
                auth_message = client_socket.recv(1024).decode('utf-8').strip()
                if not auth_message:
                    return False, None

                parts = auth_message.split(' ', 2)
                command = parts[0]

                if command == 'REGISTER':
                    if len(parts) < 3:
                        client_socket.send('REGISTER_FAILURE 命令格式错误\n'.encode('utf-8'))
                        continue

                    username = parts[1]
                    password = parts[2]
                    success, message = self.auth_manager.register_user(username, password)

                    if success:
                        client_socket.send('REGISTER_SUCCESS\n'.encode('utf-8'))
                    else:
                        client_socket.send(f'REGISTER_FAILURE {message}\n'.encode('utf-8'))

                elif command == 'LOGIN':
                    if len(parts) < 3:
                        client_socket.send('AUTH_FAILURE 命令格式错误\n'.encode('utf-8'))
                        continue

                    username = parts[1]
                    password = parts[2]
                    success, message = self.auth_manager.authenticate_user(username, password)

                    if success:
                        self.auth_manager.mark_user_online(username)
                        client_socket.send(f'AUTH_SUCCESS {username}\n'.encode('utf-8'))
                        return True, username
                    else:
                        client_socket.send(f'AUTH_FAILURE {message}\n'.encode('utf-8'))

                elif command == 'RESET_REQUEST':
                    if len(parts) < 2:
                        client_socket.send('RESET_FAILURE 命令格式错误\n'.encode('utf-8'))
                        continue

                    username = parts[1]
                    success, token_or_error = self.auth_manager.request_password_reset(username)

                    if success:
                        client_socket.send(f'RESET_TOKEN {token_or_error}\n'.encode('utf-8'))
                    else:
                        client_socket.send(f'RESET_FAILURE {token_or_error}\n'.encode('utf-8'))

                elif command == 'RESET_CONFIRM':
                    if len(parts) < 3:
                        client_socket.send('RESET_FAILURE 命令格式错误\n'.encode('utf-8'))
                        continue

                    token = parts[1]
                    new_password = parts[2]
                    success, message = self.auth_manager.reset_password(token, new_password)

                    if success:
                        client_socket.send('RESET_SUCCESS\n'.encode('utf-8'))
                    else:
                        client_socket.send(f'RESET_FAILURE {message}\n'.encode('utf-8'))

                elif command == 'DELETE_ACCOUNT':
                    if len(parts) < 3:
                        client_socket.send('DELETE_FAILURE 命令格式错误\n'.encode('utf-8'))
                        continue

                    username = parts[1]
                    password = parts[2]
                    success, message = self.auth_manager.delete_user(username, password)

                    if success:
                        client_socket.send('DELETE_SUCCESS\n'.encode('utf-8'))
                    else:
                        client_socket.send(f'DELETE_FAILURE {message}\n'.encode('utf-8'))

                elif command == 'LOGOUT':
                    return False, None

                else:
                    client_socket.send('AUTH_FAILURE 未知命令\n'.encode('utf-8'))

        except Exception as e:
            print(f"[错误] 认证处理出错: {e}")
            return False, None

    def handle_client(self, client_socket, client_address):
        """处理单个客户端连接"""
        client_name = None

        try:
            # 认证阶段
            authenticated, client_name = self.handle_authentication(client_socket)

            if not authenticated or not client_name:
                # 认证失败或用户选择退出
                return

            # 认证成功，添加到客户端列表
            with self.lock:
                self.clients.append({
                    'socket': client_socket,
                    'address': client_address,
                    'name': client_name,
                    'authenticated': True
                })

            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] 【客户端连接】{client_name} ({client_address[0]}:{client_address[1]})")

            # 广播用户加入消息
            self.broadcast(f"【系统】{client_name} 加入了聊天室", exclude_socket=client_socket)

            # 发送欢迎消息给新客户端
            client_socket.send(f"【系统】欢迎 {client_name}！当前在线用户数: {len(self.clients)}\n".encode('utf-8'))

            # 接收并广播消息
            while self.running:
                message = client_socket.recv(1024).decode('utf-8').strip()
                if not message:
                    break

                # 检查是否是登出命令
                if message == 'LOGOUT':
                    break

                timestamp = datetime.now().strftime("%H:%M:%S")
                formatted_message = f"[{timestamp}] {client_name}: {message}"
                print(formatted_message)
                self.broadcast(formatted_message, exclude_socket=client_socket)

        except ConnectionResetError:
            pass
        except Exception as e:
            if client_name:
                print(f"[错误] 处理客户端 {client_name} 时出错: {e}")
        finally:
            self.remove_client(client_socket, client_name)

    def broadcast(self, message, exclude_socket=None):
        """广播消息给所有客户端"""
        with self.lock:
            for client_info in self.clients:
                if exclude_socket is None or client_info['socket'] != exclude_socket:
                    try:
                        client_info['socket'].send((message + '\n').encode('utf-8'))
                    except Exception as e:
                        print(f"[错误] 发送消息失败: {e}")

    def remove_client(self, client_socket, client_name):
        """移除客户端"""
        with self.lock:
            self.clients = [c for c in self.clients if c['socket'] != client_socket]

        try:
            client_socket.close()
        except:
            pass

        if client_name:
            # 标记用户为离线状态
            self.auth_manager.mark_user_offline(client_name)

            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] 【客户端断开】{client_name} (在线用户数: {len(self.clients)})\n")
            self.broadcast(f"【系统】{client_name} 离开了聊天室")

    def shutdown(self):
        """关闭服务器"""
        self.running = False
        with self.lock:
            for client_info in self.clients:
                try:
                    client_info['socket'].close()
                except:
                    pass
            self.clients.clear()

        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        print("[服务器] 已关闭")

if __name__ == '__main__':
    server = ChatServer(host='0.0.0.0', port=5000)
    server.start()
