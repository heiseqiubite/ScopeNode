#!/usr/bin/env python3
"""
扫描器插件基类
定义了所有扫描器插件需要实现的接口
"""

import abc
import asyncio
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass


@dataclass
class ScanResult:
    """扫描结果数据结构"""
    target: str
    scanner_type: str
    success: bool
    results: List[Dict[str, Any]]
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class BaseScannerPlugin(abc.ABC):
    """扫描器插件基类"""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.description = ""
        self.supported_targets = []  # 支持的目标类型，如 ['url', 'ip', 'domain']
        self.result_processor_type = None  # 结果处理器类型
    
    @abc.abstractmethod
    async def scan(self, task, progress_callback=None) -> ScanResult:
        """
        执行扫描
        
        Args:
            task: 任务对象，包含目标和参数
            progress_callback: 进度回调函数
            
        Returns:
            ScanResult: 扫描结果
        """
        pass
    
    @abc.abstractmethod
    def validate_task(self, task) -> bool:
        """
        验证任务是否适用于此扫描器
        
        Args:
            task: 任务对象
            
        Returns:
            bool: 是否有效
        """
        pass
    
    @abc.abstractmethod
    def get_command_template(self) -> str:
        """
        获取命令模板
        
        Returns:
            str: 命令模板
        """
        pass
    
    async def pre_scan(self, task) -> bool:
        """
        扫描前准备
        
        Args:
            task: 任务对象
            
        Returns:
            bool: 是否准备成功
        """
        return True
    
    async def post_scan(self, task, scan_result: ScanResult) -> ScanResult:
        """
        扫描后处理
        
        Args:
            task: 任务对象
            scan_result: 扫描结果
            
        Returns:
            ScanResult: 处理后的扫描结果
        """
        return scan_result
    
    async def save_results(self, scan_result: ScanResult, task, connection_manager=None) -> bool:
        """
        保存扫描结果到数据库
        
        Args:
            scan_result: 扫描结果
            task: 任务对象
            connection_manager: 连接管理器
            
        Returns:
            bool: 是否保存成功
        """
        try:
            if not scan_result.success or not scan_result.results:
                return False
            
            # 使用插件指定的结果处理器
            if self.result_processor_type:
                from ..result_processors import get_result_processor
                processor = get_result_processor(self.result_processor_type, connection_manager)
                
                # 验证结果格式
                if not processor.validate_results(scan_result.results):
                    logging.getLogger('scanner').warning(f"Results validation failed for processor {self.result_processor_type}")
                    return False
                
                # 处理结果
                stats = await processor.process_results(scan_result.results, task)
                logging.getLogger('scanner').info(f"Results processed: {stats}")
                return True
            else:
                logging.getLogger('scanner').warning(f"No result processor specified for scanner {self.name}")
                return False
            
        except Exception as e:
            logging.getLogger('scanner').error(f"Failed to save scan results: {e}")
            return False
    
    def get_info(self) -> Dict[str, Any]:
        """
        获取扫描器插件信息
        
        Returns:
            Dict: 插件信息
        """
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'supported_targets': self.supported_targets,
            'result_processor_type': self.result_processor_type,
            'command_template': self.get_command_template()
        }
    
    async def kill_scan(self, process_id: int) -> bool:
        """
        终止扫描进程
        
        Args:
            process_id: 进程ID
            
        Returns:
            bool: 是否成功终止
        """
        try:
            import psutil
            process = psutil.Process(process_id)
            process.terminate()
            
            # 等待3秒，如果还没结束就强制杀死
            await asyncio.sleep(3)
            if process.is_running():
                process.kill()
            
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
        except Exception as e:
            logging.getLogger('scanner').error(f"Failed to kill process {process_id}: {e}")
            return False

