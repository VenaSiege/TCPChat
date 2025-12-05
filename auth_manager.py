import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Tuple, Dict, Any
import threading
import configparser


class AuthenticationManager:
    """管理用户认证、凭证存储和密码重置功能"""

    def __init__(self, credentials_file='credentials.json', config_file='config.ini'):
        """
        初始化认证管理器

        Args:
            credentials_file: 凭证存储文件路径
            config_file: 配置文件路径
        """
        self.credentials_file = credentials_file
        self.config_file = config_file
        self.credentials = {
            'users': {},
            'reset_tokens': {}
        }
        self.lock = threading.Lock()
        self.admin_code = self._load_admin_code()
        self._load_credentials()
        self._set_file_permissions()

    def register_user(self, username: str, password: str, role: str = 'user', admin_code: str = None) -> Tuple[bool, str, str]:
        """
        注册新用户账户

        Args:
            username: 用户名
            password: 密码
            role: 用户角色 ('user' 或 'admin')
            admin_code: 管理员代码（注册管理员时需要）

        Returns:
            (success: bool, message: str, role: str) 元组
        """
        with self.lock:
            # 验证密码长度
            if len(password) < 6:
                return False, "密码长度必须至少为6个字符", 'user'

            # 检查用户名是否已存在
            if username in self.credentials['users']:
                return False, "用户名已存在", 'user'

            # 如果注册管理员，验证管理员代码
            if role == 'admin':
                if admin_code is None:
                    return False, "注册管理员需要提供管理员代码", 'user'
                if not self._verify_admin_code(admin_code):
                    return False, "管理员代码错误", 'user'

            # 创建新用户账户
            password_hash = self._hash_password(password)
            self.credentials['users'][username] = {
                'password_hash': password_hash,
                'role': role,
                'created_at': datetime.now().isoformat(),
                'is_online': False
            }

            # 持久化凭证
            self._save_credentials()

            return True, "注册成功", role

    def authenticate_user(self, username: str, password: str) -> Tuple[bool, str, str]:
        """
        验证用户凭证

        Args:
            username: 用户名
            password: 密码

        Returns:
            (success: bool, message: str, role: str) 元组
        """
        with self.lock:
            # 检查用户是否存在
            if username not in self.credentials['users']:
                return False, "用户名或密码错误", 'user'

            user = self.credentials['users'][username]

            # 检查用户是否已登录
            if user.get('is_online', False):
                return False, "该用户已在其他地方登录", 'user'

            # 验证密码
            if not self._verify_password(password, user['password_hash']):
                return False, "用户名或密码错误", 'user'

            role = user.get('role', 'user')
            return True, "登录成功", role

    def is_user_logged_in(self, username: str) -> bool:
        """
        检查用户是否有活动会话

        Args:
            username: 用户名

        Returns:
            bool: 用户是否在线
        """
        with self.lock:
            if username in self.credentials['users']:
                return self.credentials['users'][username].get('is_online', False)
            return False

    def mark_user_online(self, username: str) -> None:
        """
        标记用户为在线状态

        Args:
            username: 用户名
        """
        with self.lock:
            if username in self.credentials['users']:
                self.credentials['users'][username]['is_online'] = True
                self._save_credentials()

    def mark_user_offline(self, username: str) -> None:
        """
        移除用户的活动会话

        Args:
            username: 用户名
        """
        with self.lock:
            if username in self.credentials['users']:
                self.credentials['users'][username]['is_online'] = False
                self._save_credentials()

    def request_password_reset(self, username: str) -> Tuple[bool, str]:
        """
        为用户生成重置令牌

        Args:
            username: 用户名

        Returns:
            (success: bool, token_or_error: str) 元组
        """
        with self.lock:
            # 检查用户是否存在
            if username not in self.credentials['users']:
                return False, "用户不存在"

            # 生成安全的重置令牌
            token = secrets.token_urlsafe(32)

            # 存储令牌信息
            now = datetime.now()
            expires_at = now + timedelta(minutes=30)

            self.credentials['reset_tokens'][token] = {
                'username': username,
                'created_at': now.isoformat(),
                'expires_at': expires_at.isoformat()
            }

            # 持久化凭证
            self._save_credentials()

            return True, token

    def reset_password(self, token: str, new_password: str) -> Tuple[bool, str]:
        """
        使用有效令牌重置密码

        Args:
            token: 重置令牌
            new_password: 新密码

        Returns:
            (success: bool, message: str) 元组
        """
        with self.lock:
            # 验证新密码长度
            if len(new_password) < 6:
                return False, "密码长度必须至少为6个字符"

            # 检查令牌是否存在
            if token not in self.credentials['reset_tokens']:
                return False, "无效的重置令牌"

            token_info = self.credentials['reset_tokens'][token]

            # 检查令牌是否过期
            expires_at = datetime.fromisoformat(token_info['expires_at'])
            if datetime.now() > expires_at:
                # 删除过期令牌
                del self.credentials['reset_tokens'][token]
                self._save_credentials()
                return False, "重置令牌已过期"

            # 更新密码
            username = token_info['username']
            if username in self.credentials['users']:
                password_hash = self._hash_password(new_password)
                self.credentials['users'][username]['password_hash'] = password_hash

                # 使令牌失效
                del self.credentials['reset_tokens'][token]

                # 持久化凭证
                self._save_credentials()

                return True, "密码重置成功"
            else:
                return False, "用户不存在"

    def delete_user(self, requesting_username: str, username: str, password: str) -> Tuple[bool, str]:
        """
        删除用户账户（需要凭证验证，普通用户只能删除自己的账户）

        Args:
            requesting_username: 发起删除请求的用户名
            username: 要删除的用户名
            password: 密码

        Returns:
            (success: bool, message: str) 元组
        """
        with self.lock:
            # 检查请求用户是否存在
            if requesting_username not in self.credentials['users']:
                return False, "请求用户不存在"

            requesting_user = self.credentials['users'][requesting_username]
            requesting_role = requesting_user.get('role', 'user')

            # 普通用户只能删除自己的账户
            if requesting_role != 'admin' and requesting_username != username:
                return False, "权限不足：普通用户只能删除自己的账户"

            # 检查目标用户是否存在
            if username not in self.credentials['users']:
                return False, "用户不存在"

            user = self.credentials['users'][username]

            # 验证密码
            if not self._verify_password(password, user['password_hash']):
                return False, "密码错误"

            # 检查用户是否在线（防止删除活动会话）
            if user.get('is_online', False):
                return False, "无法删除在线用户，请先退出登录"

            # 从凭证存储中删除用户
            del self.credentials['users'][username]

            # 删除与该用户关联的所有重置令牌
            tokens_to_remove = []
            for token, token_info in self.credentials['reset_tokens'].items():
                if token_info['username'] == username:
                    tokens_to_remove.append(token)

            for token in tokens_to_remove:
                del self.credentials['reset_tokens'][token]

            # 持久化更改
            self._save_credentials()

            return True, "账户删除成功"

    def get_user_role(self, username: str) -> str:
        """
        获取用户的角色

        Args:
            username: 用户名

        Returns:
            str: 用户角色 ('admin' 或 'user')，如果用户不存在返回 'user'
        """
        with self.lock:
            if username in self.credentials['users']:
                return self.credentials['users'][username].get('role', 'user')
            return 'user'

    def is_admin(self, username: str) -> bool:
        """
        检查用户是否具有管理员权限

        Args:
            username: 用户名

        Returns:
            bool: 用户是否为管理员
        """
        return self.get_user_role(username) == 'admin'

    def list_all_users(self, requesting_username: str) -> Tuple[bool, Any]:
        """
        获取所有注册用户的列表（仅管理员可访问）

        Args:
            requesting_username: 请求用户列表的用户名

        Returns:
            (success: bool, result: list[dict] or error_message: str) 元组
            成功时返回用户列表，失败时返回错误消息
        """
        with self.lock:
            # 检查请求用户是否为管理员（直接检查，避免嵌套锁）
            if requesting_username not in self.credentials['users']:
                return False, "权限不足：只有管理员可以查看用户列表"

            requesting_user_role = self.credentials['users'][requesting_username].get('role', 'user')
            if requesting_user_role != 'admin':
                return False, "权限不足：只有管理员可以查看用户列表"

            # 构建用户列表
            user_list = []
            for username, user_data in self.credentials['users'].items():
                user_list.append({
                    'username': username,
                    'role': user_data.get('role', 'user'),
                    'is_online': user_data.get('is_online', False)
                })

            return True, user_list

    def admin_delete_user(self, admin_username: str, target_username: str) -> Tuple[bool, str]:
        """
        管理员删除任意用户账户

        Args:
            admin_username: 执行删除操作的管理员用户名
            target_username: 要删除的目标用户名

        Returns:
            (success: bool, message: str) 元组
        """
        with self.lock:
            # 验证请求用户是否为管理员
            if admin_username not in self.credentials['users']:
                return False, "权限不足：只有管理员可以删除用户"

            admin_role = self.credentials['users'][admin_username].get('role', 'user')
            if admin_role != 'admin':
                return False, "权限不足：只有管理员可以删除用户"

            # 检查目标用户是否存在
            if target_username not in self.credentials['users']:
                return False, "目标用户不存在"

            # 计算管理员数量
            admin_count = sum(1 for user_data in self.credentials['users'].values()
                            if user_data.get('role', 'user') == 'admin')

            # 防止删除最后一个管理员账户
            target_user = self.credentials['users'][target_username]
            if target_user.get('role', 'user') == 'admin' and admin_count <= 1:
                return False, "无法删除最后一个管理员账户"

            # 如果目标用户在线，标记为离线（会话将被终止）
            if target_user.get('is_online', False):
                target_user['is_online'] = False

            # 从凭证存储中删除目标用户
            del self.credentials['users'][target_username]

            # 删除与该用户关联的所有重置令牌
            tokens_to_remove = []
            for token, token_info in self.credentials['reset_tokens'].items():
                if token_info['username'] == target_username:
                    tokens_to_remove.append(token)

            for token in tokens_to_remove:
                del self.credentials['reset_tokens'][token]

            # 持久化更改
            self._save_credentials()

            return True, f"用户 {target_username} 已被删除"

    def _load_admin_code(self) -> str:
        """
        从配置文件加载或生成管理员代码

        Returns:
            str: 管理员代码
        """
        config = configparser.ConfigParser()

        # 检查配置文件是否存在
        if os.path.exists(self.config_file):
            try:
                config.read(self.config_file, encoding='utf-8')
                if 'Admin' in config and 'admin_code' in config['Admin']:
                    admin_code = config['Admin']['admin_code']
                    print(f"\n{'='*60}")
                    print(f"【提示】管理员代码已配置")
                    print(f"{'='*60}\n")
                    return admin_code
            except Exception as e:
                print(f"[警告] 读取配置文件失败: {e}")

        # 生成新的管理员代码
        admin_code = secrets.token_urlsafe(16)
        self._save_admin_code(admin_code)

        print(f"\n{'='*60}")
        print(f"【重要】首次启动 - 管理员代码已生成:")
        print(f"管理员代码: {admin_code}")
        print(f"请妥善保管此代码，注册管理员账户时需要使用")
        print(f"{'='*60}\n")

        return admin_code

    def _save_admin_code(self, admin_code: str) -> None:
        """
        保存管理员代码到配置文件

        Args:
            admin_code: 管理员代码
        """
        config = configparser.ConfigParser()

        # 如果配置文件存在，先读取现有配置
        if os.path.exists(self.config_file):
            try:
                config.read(self.config_file, encoding='utf-8')
            except Exception as e:
                print(f"[警告] 读取现有配置失败: {e}")

        # 设置管理员代码
        if 'Admin' not in config:
            config['Admin'] = {}
        config['Admin']['admin_code'] = admin_code

        # 保存配置文件
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                config.write(f)

            # 设置配置文件权限（仅所有者可读写）
            if os.name != 'nt':  # 非Windows系统
                try:
                    os.chmod(self.config_file, 0o600)
                except Exception as e:
                    print(f"[警告] 无法设置配置文件权限: {e}")
        except Exception as e:
            print(f"[错误] 保存配置文件失败: {e}")

    def _verify_admin_code(self, provided_code: str) -> bool:
        """
        验证提供的管理员代码是否正确

        Args:
            provided_code: 用户提供的管理员代码

        Returns:
            bool: 代码是否正确
        """
        return provided_code == self.admin_code

    def _hash_password(self, password: str) -> str:
        """
        使用SHA256生成密码哈希

        Args:
            password: 明文密码

        Returns:
            str: 密码哈希值
        """
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def _verify_password(self, password: str, password_hash: str) -> bool:
        """
        验证密码与存储的哈希值是否匹配

        Args:
            password: 明文密码
            password_hash: 存储的哈希值

        Returns:
            bool: 密码是否匹配
        """
        return self._hash_password(password) == password_hash

    def _save_credentials(self) -> None:
        """将凭证持久化到JSON文件"""
        try:
            # 检查文件是否是新创建的
            file_exists = os.path.exists(self.credentials_file)

            with open(self.credentials_file, 'w', encoding='utf-8') as f:
                json.dump(self.credentials, f, indent=2, ensure_ascii=False)

            # 如果是新创建的文件，立即设置权限
            if not file_exists:
                self._set_file_permissions()
        except Exception as e:
            print(f"[错误] 保存凭证失败: {e}")

    def _load_credentials(self) -> None:
        """从JSON文件加载凭证"""
        if os.path.exists(self.credentials_file):
            try:
                with open(self.credentials_file, 'r', encoding='utf-8') as f:
                    loaded_data = json.load(f)
                    # 确保数据结构正确
                    if 'users' in loaded_data:
                        self.credentials['users'] = loaded_data['users']
                    if 'reset_tokens' in loaded_data:
                        self.credentials['reset_tokens'] = loaded_data['reset_tokens']
            except json.JSONDecodeError:
                print(f"[警告] 凭证文件损坏，使用空凭证存储")
                self.credentials = {'users': {}, 'reset_tokens': {}}
            except Exception as e:
                print(f"[错误] 加载凭证失败: {e}")
        else:
            # 文件不存在，创建新的凭证存储
            self._save_credentials()

    def _set_file_permissions(self) -> None:
        """设置凭证文件权限(仅所有者可读写)"""
        try:
            # 在Unix系统上设置文件权限为600
            if os.name != 'nt':  # 非Windows系统
                os.chmod(self.credentials_file, 0o600)
        except Exception as e:
            # Windows系统或权限设置失败时，记录警告但继续运行
            print(f"[警告] 无法设置文件权限: {e}")
