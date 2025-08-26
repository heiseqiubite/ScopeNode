#!/usr/bin/env python3
"""
结果处理器基类
定义了所有结果处理器需要实现的接口
"""

import abc
import logging
from typing import List, Dict, Any


class BaseResultProcessor(abc.ABC):
    """结果处理器基类"""
    
    def __init__(self, connection_manager=None):
        self.connection_manager = connection_manager
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = ""
        self.supported_formats = []  # 支持的结果格式
    
    @abc.abstractmethod
    async def process_results(self, results: List[Dict], task: Any) -> Dict[str, Any]:
        """
        处理扫描结果
        
        Args:
            results: 扫描结果列表
            task: 任务对象
            
        Returns:
            Dict: 处理统计信息
        """
        pass
    
    @abc.abstractmethod
    def validate_results(self, results: List[Dict]) -> bool:
        """
        验证结果格式是否符合此处理器
        
        Args:
            results: 扫描结果列表
            
        Returns:
            bool: 是否有效
        """
        pass
    
    async def pre_process(self, results: List[Dict], task: Any) -> List[Dict]:
        """
        预处理结果
        
        Args:
            results: 原始结果
            task: 任务对象
            
        Returns:
            List[Dict]: 预处理后的结果
        """
        return results
    
    async def post_process(self, results: List[Dict], task: Any, stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        后处理结果
        
        Args:
            results: 处理后的结果
            task: 任务对象
            stats: 处理统计信息
            
        Returns:
            Dict: 更新后的统计信息
        """
        return stats
    
    def extract_metadata(self, result: Dict) -> Dict[str, Any]:
        """
        从单个结果中提取元数据
        
        Args:
            result: 单个扫描结果
            
        Returns:
            Dict: 提取的元数据
        """
        return {}
    
    def get_info(self) -> Dict[str, Any]:
        """
        获取处理器信息
        
        Returns:
            Dict: 处理器信息
        """
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'supported_formats': self.supported_formats
        }
    
    async def ensure_connection(self):
        """确保数据库连接可用"""
        if self.connection_manager:
            await self.connection_manager.ensure_mongo_connected()
    
    def log_info(self, message: str):
        """记录信息日志"""
        logging.getLogger('scanner').info(message)
    
    def log_warning(self, message: str):
        """记录警告日志"""
        logging.getLogger('scanner').warning(message)
    
    def log_error(self, message: str):
        """记录错误日志"""
        logging.getLogger('scanner').error(message)
