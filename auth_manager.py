import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Tuple, Dict, Any
import threading


class AuthenticationManager:
    """管理用户认证、凭证存储和密码重置功能"""

    def __init__(self, credentials_file='credentials.json'):
        """
        初始化认证管理器

        Args:
            credentials_file: 凭证存储文件路径
        """
        self.credentials_file = credentials_file
        self.credentials = {
            'users': {},
            'reset_tokens': {}
        }
        self.lock = threading.Lock()
        self._load_credentials()
        self._set_file_permissions()

    def register_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        注册新用户账户

        Args:
            username: 用户名
            password: 密码

        Returns:
            (success: bool, message: str) 元组
        """
        with self.lock:
            # 验证密码长度
            if len(password) < 6:
                return False, "密码长度必须至少为6个字符"

            # 检查用户名是否已存在
            if username in self.credentials['users']:
                return False, "用户名已存在"

            # 创建新用户账户
            password_hash = self._hash_password(password)
            self.credentials['users'][username] = {
                'password_hash': password_hash,
                'created_at': datetime.now().isoformat(),
                'is_online': False
            }

            # 持久化凭证
            self._save_credentials()

            return True, "注册成功"

    def authenticate_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        验证用户凭证

        Args:
            username: 用户名
            password: 密码

        Returns:
            (success: bool, message: str) 元组
        """
        with self.lock:
            # 检查用户是否存在
            if username not in self.credentials['users']:
                return False, "用户名或密码错误"

            user = self.credentials['users'][username]

            # 检查用户是否已登录
            if user.get('is_online', False):
                return False, "该用户已在其他地方登录"

            # 验证密码
            if not self._verify_password(password, user['password_hash']):
                return False, "用户名或密码错误"

            return True, "登录成功"

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

    def delete_user(self, username: str, password: str) -> Tuple[bool, str]:
        """
        删除用户账户（需要凭证验证）

        Args:
            username: 用户名
            password: 密码

        Returns:
            (success: bool, message: str) 元组
        """
        with self.lock:
            # 检查用户是否存在
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
