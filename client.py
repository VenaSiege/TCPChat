import socket
import threading
import sys
import time
from datetime import datetime
import getpass

# Platform-specific imports for password masking
if sys.platform == 'win32':
    import msvcrt

class ChatClient:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.username = None
        self.authenticated = False
        self.user_role = None  # 'admin' or 'user'
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

    def _get_masked_password(self, prompt: str = "密码: ") -> str:
        """
        获取密码输入并用星号掩码显示

        Args:
            prompt: 提示文本

        Returns:
            str: 用户输入的密码字符串
        """
        if sys.platform == 'win32':
            # Windows: 使用 msvcrt 实现字符级输入和星号显示
            print(prompt, end='', flush=True)
            password = []
            while True:
                char = msvcrt.getch()
                if char in (b'\r', b'\n'):  # Enter键
                    print()  # 换行
                    break
                elif char == b'\x08':  # Backspace键
                    if password:
                        password.pop()
                        # 删除一个星号：退格、空格、退格
                        print('\b \b', end='', flush=True)
                elif char == b'\x03':  # Ctrl+C
                    print()
                    raise KeyboardInterrupt
                else:
                    try:
                        # 尝试解码字符
                        decoded_char = char.decode('utf-8')
                        password.append(decoded_char)
                        print('*', end='', flush=True)
                    except UnicodeDecodeError:
                        # 忽略无法解码的字符
                        pass
            return ''.join(password)
        else:
            # Unix/Linux/macOS: 使用 getpass (隐藏输入，不显示星号)
            return getpass.getpass(prompt)

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
                print("3. 注册为管理员")
                print("4. 重置密码")
                print("5. 删除账户")
                print("6. 退出")
                print("=" * 50)

                choice = input("请选择操作 (1-6): ").strip()

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
                    if self.register_admin():
                        # 注册成功后自动登录
                        print("\n管理员注册成功！请登录。")
                    # 如果连接断开，尝试重新连接
                    if not self.connected:
                        if not self._handle_connection_loss():
                            return False

                elif choice == '4':
                    self.request_password_reset()
                    # 如果连接断开，尝试重新连接
                    if not self.connected:
                        if not self._handle_connection_loss():
                            return False

                elif choice == '5':
                    if self.delete_account():
                        # 删除成功，断开连接并退出
                        return False
                    # 如果连接断开，尝试重新连接
                    if not self.connected:
                        if not self._handle_connection_loss():
                            return False

                elif choice == '6':
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

            password = self._get_masked_password("密码: ").strip()
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
                # AUTH_SUCCESS format: AUTH_SUCCESS <username> <role>
                parts = response.split()
                if len(parts) >= 3:
                    self.username = parts[1]
                    self.user_role = parts[2]
                    self.authenticated = True
                    role_display = '管理员' if self.user_role == 'admin' else '普通用户'
                    self._display_success(f"登录成功！欢迎 {self.username} ({role_display})")
                    return True
                else:
                    self._display_error("服务器响应格式错误")
                    return False
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

            password = self._get_masked_password("密码 (至少6个字符): ").strip()

            # 验证密码长度
            if len(password) < 6:
                self._display_error("密码长度必须至少为6个字符")
                return False

            confirm_password = self._get_masked_password("确认密码: ").strip()
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

    def register_admin(self) -> bool:
        """
        处理管理员注册流程

        Returns:
            bool: 注册成功返回True，否则返回False
        """
        try:
            print("\n--- 注册管理员账户 ---")
            print("注意：注册管理员需要提供管理员代码")

            username = input("用户名: ").strip()
            if not username:
                self._display_error("用户名不能为空")
                return False

            password = self._get_masked_password("密码 (至少6个字符): ").strip()

            # 验证密码长度
            if len(password) < 6:
                self._display_error("密码长度必须至少为6个字符")
                return False

            confirm_password = self._get_masked_password("确认密码: ").strip()
            if password != confirm_password:
                self._display_error("两次输入的密码不一致")
                return False

            admin_code = input("管理员代码: ").strip()
            if not admin_code:
                self._display_error("管理员代码不能为空")
                return False

            # 发送管理员注册命令
            register_command = f"REGISTER {username} {password} admin {admin_code}"
            if not self._send_auth_command(register_command):
                return False

            # 接收并解析服务器响应
            response = self._receive_auth_response()
            if not response:
                return False

            # 解析响应
            if response.startswith('REGISTER_SUCCESS'):
                self._display_success("管理员注册成功！")
                return True
            elif response.startswith('REGISTER_FAILURE'):
                _, error_msg = self._parse_response(response, 'REGISTER_SUCCESS')
                self._display_error(error_msg)
                return False
            else:
                self._display_error("未知的服务器响应")
                return False

        except KeyboardInterrupt:
            print("\n[系统] 管理员注册操作已取消")
            return False
        except Exception as e:
            self._display_error(f"管理员注册过程出错: {e}")
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

            new_password = self._get_masked_password("新密码 (至少6个字符): ").strip()

            # 验证密码长度
            if len(new_password) < 6:
                self._display_error("密码长度必须至少为6个字符")
                return

            confirm_password = self._get_masked_password("确认新密码: ").strip()
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

    def delete_account(self) -> bool:
        """
        处理账户删除流程

        Returns:
            bool: 删除成功返回True，否则返回False
        """
        try:
            print("\n--- 删除账户 ---")
            print("警告：此操作无法撤销！")

            username = input("用户名: ").strip()
            if not username:
                self._display_error("用户名不能为空")
                return False

            password = self._get_masked_password("密码: ").strip()
            if not password:
                self._display_error("密码不能为空")
                return False

            # 确认提示
            confirmation = input("\n您确定要删除此账户吗？此操作无法撤销！(yes/no): ").strip().lower()
            if confirmation != 'yes':
                print("[系统] 账户删除已取消")
                return False

            # 发送删除账户命令
            delete_command = f"DELETE_ACCOUNT {username} {password}"
            if not self._send_auth_command(delete_command):
                return False

            # 接收并解析服务器响应
            response = self._receive_auth_response()
            if not response:
                return False

            # 解析响应
            if response.startswith('DELETE_SUCCESS'):
                self._display_success("账户已成功删除")
                print("[客户端] 正在断开连接...")
                self.connected = False
                return True
            elif response.startswith('DELETE_FAILURE'):
                _, error_msg = self._parse_response(response, 'DELETE_SUCCESS')
                self._display_error(error_msg)
                return False
            else:
                self._display_error("未知的服务器响应")
                return False

        except KeyboardInterrupt:
            print("\n[系统] 账户删除操作已取消")
            return False
        except Exception as e:
            self._display_error(f"账户删除过程出错: {e}")
            return False

    def list_users(self) -> None:
        """
        处理用户列表请求流程（仅管理员）

        显示所有注册用户的用户名、角色和在线状态
        """
        try:
            import json

            print("\n--- 用户列表 ---")

            # 发送用户列表请求命令（需要包含当前用户名）
            if not self.username:
                self._display_error("未登录，无法获取用户列表")
                return

            list_command = f"LIST_USERS {self.username}"
            if not self._send_auth_command(list_command):
                return

            # 接收并解析服务器响应
            response = self._receive_auth_response()
            if not response:
                return

            # 解析响应
            if response.startswith('USER_LIST '):
                # 提取JSON数据
                json_start = response.find(' ') + 1
                json_data = response[json_start:].strip()

                try:
                    user_list = json.loads(json_data)

                    # 检查是否为空列表
                    if not user_list:
                        print("\n当前系统中没有注册用户。")
                        return

                    # 显示格式化的用户列表
                    print("\n" + "=" * 60)
                    print(f"{'用户名':<20} {'角色':<10} {'状态':<10}")
                    print("=" * 60)

                    for user in user_list:
                        username = user.get('username', 'N/A')
                        role = user.get('role', 'N/A')
                        is_online = user.get('is_online', False)
                        status = '在线' if is_online else '离线'

                        # 格式化角色显示
                        role_display = '管理员' if role == 'admin' else '普通用户'

                        print(f"{username:<20} {role_display:<10} {status:<10}")

                    print("=" * 60)
                    print(f"总计: {len(user_list)} 个用户\n")

                except json.JSONDecodeError as e:
                    self._display_error(f"解析用户列表数据失败: {e}")
                except Exception as e:
                    self._display_error(f"处理用户列表数据失败: {e}")

            elif response.startswith('USER_LIST_FAILURE'):
                _, error_msg = self._parse_response(response, 'USER_LIST')
                self._display_error(error_msg)
            else:
                self._display_error("未知的服务器响应")

        except KeyboardInterrupt:
            print("\n[系统] 用户列表操作已取消")
        except Exception as e:
            self._display_error(f"获取用户列表过程出错: {e}")

    def admin_delete_user(self) -> None:
        """
        处理管理员删除用户流程（仅管理员）

        首先显示用户列表，然后提示输入目标用户名并确认删除
        """
        try:
            print("\n--- 管理员删除用户 ---")

            # 检查是否已登录
            if not self.username:
                self._display_error("未登录，无法执行管理员操作")
                return

            # 首先显示用户列表
            print("正在获取用户列表...")
            self.list_users()

            # 提示输入目标用户名
            print("\n请输入要删除的用户名")
            target_username = input("目标用户名: ").strip()
            if not target_username:
                self._display_error("用户名不能为空")
                return

            # 确认提示
            print(f"\n警告：您即将删除用户 '{target_username}'")
            print("此操作无法撤销！")
            confirmation = input("确认删除此用户？(yes/no): ").strip().lower()
            if confirmation != 'yes':
                print("[系统] 删除操作已取消")
                return

            # 发送管理员删除命令
            # 命令格式: ADMIN_DELETE_USER <admin_username> <target_username>
            delete_command = f"ADMIN_DELETE_USER {self.username} {target_username}"
            if not self._send_auth_command(delete_command):
                return

            # 接收并解析服务器响应
            response = self._receive_auth_response()
            if not response:
                return

            # 解析响应
            if response.startswith('ADMIN_DELETE_SUCCESS'):
                parts = response.split()
                deleted_username = parts[1] if len(parts) > 1 else target_username
                self._display_success(f"用户 '{deleted_username}' 已成功删除")
            elif response.startswith('ADMIN_DELETE_FAILURE'):
                _, error_msg = self._parse_response(response, 'ADMIN_DELETE_SUCCESS')
                self._display_error(error_msg)
            else:
                self._display_error("未知的服务器响应")

        except KeyboardInterrupt:
            print("\n[系统] 管理员删除操作已取消")
        except Exception as e:
            self._display_error(f"管理员删除过程出错: {e}")

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
            except socket.timeout:
                # 超时是正常的，继续等待消息
                continue
            except ConnectionResetError:
                self.connected = False
                print("\n[系统] 服务器已断开连接")
                break
            except Exception as e:
                if self.connected:
                    print(f"\n[错误] 接收消息失败: {e}")
                break

    def show_admin_menu(self) -> None:
        """
        显示管理员菜单并处理管理员操作

        仅当用户角色为管理员时显示此菜单
        """
        if self.user_role != 'admin':
            self._display_error("此功能仅限管理员使用")
            return

        try:
            print("\n" + "=" * 50)
            print("         管理员菜单")
            print("=" * 50)
            print("1. 查看用户列表")
            print("2. 删除用户")
            print("3. 返回聊天")
            print("=" * 50)

            choice = input("请选择操作 (1-3): ").strip()

            if choice == '1':
                self.list_users()
            elif choice == '2':
                self.admin_delete_user()
            elif choice == '3':
                print("[系统] 返回聊天界面")
            else:
                print("[错误] 无效的选择")

        except KeyboardInterrupt:
            print("\n[系统] 管理员菜单操作已取消")
        except Exception as e:
            self._display_error(f"管理员菜单操作出错: {e}")

    def send_messages(self):
        """发送消息到服务器"""
        print("开始聊天 (输入 'exit' 或 'logout' 退出):\n")
        if self.user_role == 'admin':
            print("管理员命令: /admin - 打开管理员菜单\n")
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

                # 处理管理员命令
                if message.lower() == '/admin':
                    if self.user_role == 'admin':
                        self.show_admin_menu()
                    else:
                        self._display_error("此命令仅限管理员使用")
                    print("> ", end='', flush=True)
                    continue

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

            # 进入聊天阶段后，设置较长的超时时间以保持长连接
            # 使用较长的超时（300秒 = 5分钟）而不是完全阻塞，以便能够检测连接问题
            self.socket.settimeout(300)

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
