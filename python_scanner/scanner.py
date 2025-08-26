import asyncio
import logging
from typing import Dict, Any, Optional, Callable
from .scanners import get_scanner_plugin, AVAILABLE_SCANNERS
from .scanners.base import ScanResult


class ScannerEngine:
    """重构后的扫描引擎，支持插件化扫描器"""
    
    def __init__(self, connection_manager=None):
        self.default_scanner = "gogo"  # 默认扫描器类型
        self.connection_manager = connection_manager
        logging.getLogger('scanner').info(f"Scanner engine initialized with available scanners: {list(AVAILABLE_SCANNERS.keys())}")
    
    def get_scanner_for_task(self, task) -> str:
        """根据任务确定使用哪个扫描器"""
        # 可以根据任务参数或类型来决定使用哪个扫描器
        # 目前默认使用gogo扫描器
        
        # 检查任务中是否指定了扫描器类型
        if hasattr(task, 'parameters') and task.parameters:
            scanner_type = task.parameters.get('scanner_type')
            if scanner_type and scanner_type in AVAILABLE_SCANNERS:
                return scanner_type
        
        # 检查任务类型
        if hasattr(task, 'type') and task.type:
            if 'vuln' in task.type.lower() or 'gogo' in task.type.lower():
                return 'gogo'
        
        # 默认返回gogo扫描器
        return self.default_scanner
    
    async def _create_progress_callback(self, task) -> Callable:
        """创建进度回调函数"""
        async def progress_callback(stage: str, status: str = "start"):
            # 这里可以集成原来的进度报告逻辑
            # 目前简化为日志记录
            logging.getLogger('scanner').debug(f"Task {task.id} progress: {stage} - {status}")
        
        return progress_callback
    
    async def run_scan_with_pid(self, task) -> int:
        """运行扫描并返回进程ID（兼容原有接口）"""
        try:
            # 确定使用的扫描器
            scanner_type = self.get_scanner_for_task(task)
            scanner_plugin = get_scanner_plugin(scanner_type)
            
            logging.getLogger('scanner').info(f"Using scanner: {scanner_type} for task {task.id}")
            
            # 验证任务
            if not scanner_plugin.validate_task(task):
                raise ValueError(f"Task validation failed for scanner {scanner_type}")
            
            # 创建进度回调
            progress_callback = await self._create_progress_callback(task)
            
            # 执行扫描前准备
            if not await scanner_plugin.pre_scan(task):
                raise RuntimeError("Pre-scan preparation failed")
            
            # 执行扫描
            scan_result = await scanner_plugin.scan(task, progress_callback)
            
            # 扫描后处理
            scan_result = await scanner_plugin.post_scan(task, scan_result)
            
            if scan_result.success:
                # 保存结果
                success = await scanner_plugin.save_results(scan_result, task, self.connection_manager)
                if not success:
                    logging.getLogger('scanner').warning(f"Failed to save scan results for task {task.id}")
                
                logging.getLogger('scanner').info(f"Scan completed successfully for task {task.id}")
                
                # 返回进程ID（从元数据中获取）
                return scan_result.metadata.get('process_id', 0)
            else:
                error_msg = scan_result.error_message or "Unknown scan error"
                logging.getLogger('scanner').error(f"Scan failed for task {task.id}: {error_msg}")
                raise Exception(error_msg)
            
        except Exception as e:
            logging.getLogger('scanner').error(f"Scanner engine failed for task {task.id}: {e}")
            raise
    
    async def run_scan(self, task):
        """运行扫描（兼容性方法）"""
        await self.run_scan_with_pid(task)
    
    async def scan_with_plugin(self, task, scanner_type: str = None) -> ScanResult:
        """使用指定插件进行扫描（新接口）"""
        if scanner_type is None:
            scanner_type = self.get_scanner_for_task(task)
        
        if scanner_type not in AVAILABLE_SCANNERS:
            raise ValueError(f"Unknown scanner type: {scanner_type}")
        
        scanner_plugin = get_scanner_plugin(scanner_type)
        
        # 验证任务
        if not scanner_plugin.validate_task(task):
            raise ValueError(f"Task validation failed for scanner {scanner_type}")
        
        # 创建进度回调
        progress_callback = await self._create_progress_callback(task)
        
        # 执行扫描前准备
        if not await scanner_plugin.pre_scan(task):
            raise RuntimeError("Pre-scan preparation failed")
        
        # 执行扫描
        scan_result = await scanner_plugin.scan(task, progress_callback)
        
        # 扫描后处理
        scan_result = await scanner_plugin.post_scan(task, scan_result)
        
        return scan_result
    
    def get_available_scanners(self) -> Dict[str, Dict[str, Any]]:
        """获取可用的扫描器信息"""
        scanners_info = {}
        for scanner_type, scanner_class in AVAILABLE_SCANNERS.items():
            try:
                plugin = scanner_class()
                scanners_info[scanner_type] = plugin.get_info()
            except Exception as e:
                logging.getLogger('scanner').error(f"Failed to get info for scanner {scanner_type}: {e}")
                scanners_info[scanner_type] = {"error": str(e)}
        
        return scanners_info
    
    async def kill_scan_process(self, process_id: int, scanner_type: str = None) -> bool:
        """终止扫描进程"""
        if scanner_type is None:
            scanner_type = self.default_scanner
        
        try:
            scanner_plugin = get_scanner_plugin(scanner_type)
            return await scanner_plugin.kill_scan(process_id)
        except Exception as e:
            logging.getLogger('scanner').error(f"Failed to kill scan process {process_id}: {e}")
            return False
    
    
    
