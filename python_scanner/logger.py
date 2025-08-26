import logging
import json
from datetime import datetime
from typing import Optional
from .config import config
from .connections import connection_manager

class ScannerLogger:
    def __init__(self):
        self._setup_logger()
        self.connection_manager = connection_manager
        self._setup_redis()
    
    def _setup_logger(self):
        """设置本地日志"""
        self.logger = logging.getLogger('scanner')
        self.logger.setLevel(logging.DEBUG if config.debug else logging.INFO)
        
        # 检查是否已经配置过处理器，避免重复添加
        if self.logger.handlers:
            return
        
        # 创建格式化器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # 创建文件处理器
        file_handler = logging.FileHandler('scanner.log', encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
    
    def _setup_redis(self):
        """设置Redis连接"""
        try:
            self.connection_manager.setup_redis(use_pool=False)  # 日志使用简单连接
        except Exception as e:
            self.logger.error(f"Failed to setup Redis connection in Logger: {e}")
    
    def _send_to_redis(self, level: str, message: str):
        """发送日志到Redis"""
        redis_client = self.connection_manager.redis
        if not redis_client:
            return
        
        try:
            log_msg = {
                "name": config.node_name,
                "log": f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - [{level}] {message}\n"
            }
            redis_client.publish("logs", json.dumps(log_msg, ensure_ascii=False))
        except Exception as e:
            self.logger.error(f"Failed to send log to Redis: {e}")
    
    def info(self, message: str, send_to_redis: bool = True):
        """记录INFO级别日志"""
        self.logger.info(message)
        if send_to_redis:
            self._send_to_redis("INFO", message)
    
    def warning(self, message: str, send_to_redis: bool = True):
        """记录WARNING级别日志"""
        self.logger.warning(message)
        if send_to_redis:
            self._send_to_redis("WARNING", message)
    
    def error(self, message: str, send_to_redis: bool = True):
        """记录ERROR级别日志"""
        self.logger.error(message)
        if send_to_redis:
            self._send_to_redis("ERROR", message)
    
    def debug(self, message: str, send_to_redis: bool = True):
        """记录DEBUG级别日志"""
        self.logger.debug(message)
        if config.debug and send_to_redis:
            self._send_to_redis("DEBUG", message)
    
    def info_local(self, message: str):
        """只记录本地INFO日志"""
        self.info(message, send_to_redis=False)
    
    def error_local(self, message: str):
        """只记录本地ERROR日志"""
        self.error(message, send_to_redis=False)
    
    def debug_local(self, message: str):
        """只记录本地DEBUG日志"""
        self.debug(message, send_to_redis=False)

# 全局日志实例
logger = ScannerLogger() 