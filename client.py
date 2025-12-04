import socket
import threading
import sys
import time
from datetime import datetime

class ChatClient:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.username = None
        self.authenticated = False
        self.connection_timeout = 10  # 连接超时时间（秒）
        self.socket_timeout = 5  # socket操作超时时间（秒）
        self.max_retries = 3  # 最大重试次数

    def _send_auth_command(self, command: str) -> bool:
        """
        发送认证协议命令到服务器

        Args:
            command: 要发送的命令字符串

        Returns:
            bool: 发送成功返回True，否则返回False
        """
        try:
            self.socket.send(command.encode('utf-8'))
            return True
        except socket.timeout:
            self._display_error("发送命令超时，请检查网络连接")
            return False
        except ConnectionResetError:
            self._display_error("连接已被服务器重置")
            self.connected = False
            return False
        except BrokenPipeError:
            self._display_error("连接已断开")
            self.connected = False
            return False
        except OSError as e:
            self._display_error(f"网络错误: {e}")
            self.connected = False
            return False
        except Exception as e:
            self._display_error(f"发送命令失败: {e}")
            return False

    def _receive_auth_response(self) -> str:
        """
        接收服务器的认证协议响应

        Returns:
            str: 服务器响应字符串，失败返回空字符串
        """
        try:
            response = self.socket.recv(1024).decode('utf-8').strip()
            if not response:
                self._display_error("服务器关闭了连接")
                self.connected = False
            return response
        except socket.timeout:
            self._display_error("接收响应超时，请检查网络连接")
            return ""
        except ConnectionResetError:
            self._display_error("连接已被服务器重置")
            self.connected = False
            return ""
        except OSError as e:
            self._display_error(f"网络错误: {e}")
            self.connected = False
            return ""
        except UnicodeDecodeError:
            self._display_error("接收到无效的数据格式")
            return ""
        except Exception as e:
            self._display_error(f"接收响应失败: {e}")
            return ""

    def _parse_response(self, response: str, expected_prefix: str) -> tuple[bool, str]:
        """
        解析服务器响应

        Args:
            response: 服务器响应字符串
            expected_prefix: 期望的成功响应前缀

        Returns:
            tuple[bool, str]: (是否成功, 消息内容)
        """
        if not response:
            return False, "未收到服务器响应"

        if response.startswith(expected_prefix):
            parts = response.split(' ', 1)
            message = parts[1] if len(parts) > 1 else ""
            return True, message
        else:
            # 尝试解析错误响应
            parts = response.split(' ', 1)
            error_msg = parts[1] if len(parts) > 1 else "操作失败"
            return False, error_msg

    def _display_success(self, message: str) -> None:
        """
        显示成功消息（带时间戳）

        Args:
            message: 要显示的消息
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] 【成功】{message}")

    def _display_error(self, message: str) -> None:
        """
        显示错误消息（带时间戳）

        Args:
            message: 要显示的错误消息
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] 【错误】{message}")

    def _handle_connection_loss(self) -> bool:
        """
        处理连接丢失，提供重新连接选项

        Returns:
            bool: 如果重新连接成功返回True，否则返回False
        """
        print("\n[系统] 检测到连接丢失")
        retry = input("是否尝试重新连接？(y/n): ").strip().lower()

        if retry == 'y':
            # 清理旧连接
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass

            # 尝试重新连接
            if self.connect():
                print("[系统] 重新连接成功，请重新进行认证")
                return True
            else:
                print("[系统] 重新连接失败")
                return False
        else:
            print("[客户端] 用户选择不重新连接")
            return False

    def connect(self):
        """连接到服务器，带重试逻辑"""
        retry_count = 0

        while retry_count < self.max_retries:
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(self.connection_timeout)

                if retry_count > 0:
                    print(f"[客户端] 正在尝试重新连接... (尝试 {retry_count + 1}/{self.max_retries})")

                self.socket.connect((self.host, self.port))

                # 连接成功后设置socket超时
                self.socket.settimeout(self.socket_timeout)
                self.connected = True
                print(f"[客户端] 已连接到 {self.host}:{self.port}\n")
                return True

            except socket.timeout:
                print(f"[错误] 连接超时 ({self.connection_timeout}秒)")
                retry_count += 1
                if retry_count < self.max_retries:
                    print(f"[提示] 将在2秒后重试...")
                    time.sleep(2)

            except ConnectionRefusedError:
                print(f"[错误] 无法连接到服务器 {self.host}:{self.port}")
                print("[提示] 请确保服务器已启动")
                retry_count += 1
                if retry_count < self.max_retries:
                    retry = input("是否重试连接？(y/n): ").strip().lower()
                    if retry != 'y':
                        return False
                    time.sleep(1)

            except socket.gaierror:
                print(f"[错误] 无法解析主机名: {self.host}")
                print("[提示] 请检查服务器地址是否正确")
                return False

            except OSError as e:
                print(f"[错误] 网络错误: {e}")
                retry_count += 1
                if retry_count < self.max_retries:
                    print(f"[提示] 将在2秒后重试...")
                    time.sleep(2)

            except Exception as e:
                print(f"[错误] 连接失败: {e}")
                retry_count += 1
                if retry_count < self.max_retries:
                    print(f"[提示] 将在2秒后重试...")
                    time.sleep(2)

        print(f"[错误] 连接失败，已达到最大重试次数 ({self.max_retries})")
        return False

    def authenticate(self) -> bool:
        """
        呈现认证菜单并处理用户选择

        Returns:
            bool: 如果认证成功返回True，否则返回False
        """
        while not self.authenticated and self.connected:
            try:
                print("\n" + "=" * 50)
                print("         认证菜单")
                print("=" * 50)
                print("1. 登录")
                print("2. 注册")
                print("3. 重置密码")
                print("4. 退出")
                print("=" * 50)

                choice = input("请选择操作 (1-4): ").strip()

                if choice == '1':
                    if self.login():
                        return True
                    # 如果连接断开，尝试重新连接
                    if not self.connected:
                        if not self._handle_connection_loss():
                            return False

                elif choice == '2':
                    if self.register():
                        # 注册成功后自动登录
                        print("\n注册成功！请登录。")
                    # 如果连接断开，尝试重新连接
                    if not self.connected:
                        if not self._handle_connection_loss():
                            return False

                elif choice == '3':
                    self.request_password_reset()
                    # 如果连接断开，尝试重新连接
                    if not self.connected:
                        if not self._handle_connection_loss():
                            return False

                elif choice == '4':
                    print("[客户端] 退出")
                    return False
                else:
                    print("[错误] 无效的选择，请重试")

            except KeyboardInterrupt:
                print("\n[客户端] 用户中断操作")
                return False
            except Exception as e:
                self._display_error(f"认证过程出错: {e}")
                # 不崩溃，继续显示菜单
                continue

        return self.authenticated

    def login(self) -> bool:
        """
        处理登录流程

        Returns:
            bool: 登录成功返回True，否则返回False
        """
        try:
            print("\n--- 登录 ---")
            username = input("用户名: ").strip()
            if not username:
                self._display_error("用户名不能为空")
                return False

            password = input("密码: ").strip()
            if not password:
                self._display_error("密码不能为空")
                return False

            # 发送登录命令
            login_command = f"LOGIN {username} {password}"
            if not self._send_auth_command(login_command):
                return False

            # 接收并解析服务器响应
            response = self._receive_auth_response()
            if not response:
                return False

            # 解析响应
            if response.startswith('AUTH_SUCCESS'):
                success, returned_username = self._parse_response(response, 'AUTH_SUCCESS')
                if success:
                    self.username = returned_username if returned_username else username
                    self.authenticated = True
                    self._display_success(f"登录成功！欢迎 {self.username}")
                    return True
            elif response.startswith('AUTH_FAILURE'):
                _, error_msg = self._parse_response(response, 'AUTH_SUCCESS')
                self._display_error(error_msg)
                return False
            else:
                self._display_error("未知的服务器响应")
                return False

        except KeyboardInterrupt:
            print("\n[系统] 登录操作已取消")
            return False
        except Exception as e:
            self._display_error(f"登录过程出错: {e}")
            return False

    def register(self) -> bool:
        """
        处理注册流程

        Returns:
            bool: 注册成功返回True，否则返回False
        """
        try:
            print("\n--- 注册新账户 ---")
            username = input("用户名: ").strip()
            if not username:
                self._display_error("用户名不能为空")
                return False

            password = input("密码 (至少6个字符): ").strip()

            # 验证密码长度
            if len(password) < 6:
                self._display_error("密码长度必须至少为6个字符")
                return False

            confirm_password = input("确认密码: ").strip()
            if password != confirm_password:
                self._display_error("两次输入的密码不一致")
                return False

            # 发送注册命令
            register_command = f"REGISTER {username} {password}"
            if not self._send_auth_command(register_command):
                return False

            # 接收并解析服务器响应
            response = self._receive_auth_response()
            if not response:
                return False

            # 解析响应
            if response.startswith('REGISTER_SUCCESS'):
                self._display_success("注册成功！")
                return True
            elif response.startswith('REGISTER_FAILURE'):
                _, error_msg = self._parse_response(response, 'REGISTER_SUCCESS')
                self._display_error(error_msg)
                return False
            else:
                self._display_error("未知的服务器响应")
                return False

        except KeyboardInterrupt:
            print("\n[系统] 注册操作已取消")
            return False
        except Exception as e:
            self._display_error(f"注册过程出错: {e}")
            return False

    def request_password_reset(self) -> None:
        """处理密码重置请求流程"""
        try:
            print("\n--- 密码重置 ---")
            username = input("用户名: ").strip()
            if not username:
                self._display_error("用户名不能为空")
                return

            # 发送重置请求命令
            reset_command = f"RESET_REQUEST {username}"
            if not self._send_auth_command(reset_command):
                return

            # 接收并解析服务器响应
            response = self._receive_auth_response()
            if not response:
                return

            # 解析响应
            if response.startswith('RESET_TOKEN'):
                success, token = self._parse_response(response, 'RESET_TOKEN')
                if success and token:
                    self._display_success("重置令牌已生成")
                    print(f"令牌: {token}")
                    print("请保存此令牌，它将在30分钟后过期。")

                    # 询问是否立即确认重置
                    confirm = input("\n是否立即使用此令牌重置密码？(y/n): ").strip().lower()
                    if confirm == 'y':
                        self.confirm_password_reset(token)
                else:
                    self._display_error("服务器响应格式错误")
            elif response.startswith('RESET_FAILURE'):
                _, error_msg = self._parse_response(response, 'RESET_TOKEN')
                self._display_error(error_msg)
            else:
                self._display_error("未知的服务器响应")

        except KeyboardInterrupt:
            print("\n[系统] 密码重置操作已取消")
        except Exception as e:
            self._display_error(f"密码重置过程出错: {e}")

    def confirm_password_reset(self, token: str = None) -> None:
        """
        处理密码重置确认流程

        Args:
            token: 重置令牌（可选，如果未提供则提示用户输入）
        """
        try:
            print("\n--- 确认密码重置 ---")

            if token is None:
                token = input("重置令牌: ").strip()
                if not token:
                    self._display_error("令牌不能为空")
                    return

            new_password = input("新密码 (至少6个字符): ").strip()

            # 验证密码长度
            if len(new_password) < 6:
                self._display_error("密码长度必须至少为6个字符")
                return

            confirm_password = input("确认新密码: ").strip()
            if new_password != confirm_password:
                self._display_error("两次输入的密码不一致")
                return

            # 发送重置确认命令
            reset_confirm_command = f"RESET_CONFIRM {token} {new_password}"
            if not self._send_auth_command(reset_confirm_command):
                return

            # 接收并解析服务器响应
            response = self._receive_auth_response()
            if not response:
                return

            # 解析响应
            if response.startswith('RESET_SUCCESS'):
                self._display_success("密码重置成功！请使用新密码登录。")
            elif response.startswith('RESET_FAILURE'):
                _, error_msg = self._parse_response(response, 'RESET_SUCCESS')
                self._display_error(error_msg)
            else:
                self._display_error("未知的服务器响应")

        except KeyboardInterrupt:
            print("\n[系统] 密码重置确认操作已取消")
        except Exception as e:
            self._display_error(f"密码重置确认过程出错: {e}")

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
        print("开始聊天 (输入 'exit' 或 'logout' 退出):\n")
        print("> ", end='', flush=True)

        try:
            while self.connected:
                message = input().strip()

                if message.lower() in ['exit', 'logout']:
                    print("[客户端] 正在断开连接...")
                    # 如果是logout命令且已认证，发送LOGOUT命令到服务器
                    if message.lower() == 'logout' and self.authenticated:
                        try:
                            self.socket.send("LOGOUT".encode('utf-8'))
                        except:
                            pass  # 忽略发送失败，继续断开连接
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
        try:
            if not self.connect():
                return

            # 进行认证，只有认证成功才能进入聊天阶段
            if not self.authenticate():
                print("[客户端] 认证失败或用户取消，退出")
                return

            # 认证成功后进入聊天阶段
            print("\n" + "=" * 50)
            print("         进入聊天室")
            print("=" * 50)
            print(f"欢迎 {self.username}！")
            print()

            # 创建接收消息的线程
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

            # 主线程处理发送消息
            self.send_messages()

        except KeyboardInterrupt:
            print("\n[客户端] 用户中断")
        except Exception as e:
            print(f"\n[错误] 客户端运行出错: {e}")
        finally:
            self.disconnect()

    def disconnect(self):
        """断开连接并清理资源"""
        self.connected = False
        self.authenticated = False
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
