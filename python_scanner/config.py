import os
import yaml
from typing import Dict, Any
from dataclasses import dataclass
import socket
import random
import string

@dataclass
class RedisConfig:
    host: str
    port: int
    password: str = ""
    
@dataclass
class MongoDBConfig:
    host: str
    port: int
    username: str = ""
    password: str = ""
    database: str = ""

@dataclass
class ScannerConfig:
    node_name: str
    version: str = "1.0.0"
    max_task_num: int = 10
    debug: bool = False
    redis: RedisConfig = None
    mongodb: MongoDBConfig = None

class ConfigManager:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
    
    def _generate_node_name(self) -> str:
        """生成节点名称"""
        hostname = socket.gethostname()
        random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        return f"{hostname}-{random_suffix}"
    
    def _load_config(self) -> ScannerConfig:
        """加载配置文件"""
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
        else:
            # 从环境变量加载配置
            data = {
                'node_name': os.getenv('NODE_NAME', self._generate_node_name()),
                'version': os.getenv('VERSION', '1.0.0'),
                'max_task_num': int(os.getenv('MAX_TASK_NUM', '10')),
                'debug': os.getenv('DEBUG', 'false').lower() == 'true',
                'redis': {
                    'host': os.getenv('REDIS_HOST', 'localhost'),
                    'port': int(os.getenv('REDIS_PORT', '6379')),
                    'password': os.getenv('REDIS_PASSWORD', '')
                },
                'mongodb': {
                    'host': os.getenv('MONGODB_HOST', 'localhost'),
                    'port': int(os.getenv('MONGODB_PORT', '27017')),
                    'username': os.getenv('MONGODB_USERNAME', ''),
                    'password': os.getenv('MONGODB_PASSWORD', ''),
                    'database': os.getenv('MONGODB_DATABASE', 'scope_sentry')
                }
            }
            self._save_config(data)
        
        redis_config = RedisConfig(**data.get('redis', {}))
        mongodb_config = MongoDBConfig(**data.get('mongodb', {}))
        
        return ScannerConfig(
            node_name=data.get('node_name'),
            version=data.get('version', '1.0.0'),
            max_task_num=data.get('max_task_num', 10),
            debug=data.get('debug', False),
            redis=redis_config,
            mongodb=mongodb_config
        )
    
    def _save_config(self, data: Dict[str, Any]):
        """保存配置到文件"""
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

# 全局配置实例
config = ConfigManager().config 