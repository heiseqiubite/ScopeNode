import asyncio
import time
import json
import psutil
from datetime import datetime
from typing import Dict, Any
from .config import config
from .logger import logger
from .connections import connection_manager

class NodeManager:
    def __init__(self):
        self.connection_manager = connection_manager
        self.running_tasks = 0
        self.finished_tasks = 0
        self.is_running = False
        self._setup_redis()
    
    def _setup_redis(self):
        """设置Redis连接"""
        try:
            self.connection_manager.setup_redis(use_pool=False)  # 节点管理器使用简单连接
            logger.info(f"NodeManager Redis connection established")
        except Exception as e:
            logger.error(f"Failed to setup Redis connection in NodeManager: {e}")
            raise
    
    def _get_system_info(self) -> Dict[str, Any]:
        """获取系统信息"""
        memory = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=1)
        
        return {
            "updateTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "running": self.running_tasks,
            "finished": self.finished_tasks,
            "cpuNum": round(cpu_percent, 2),
            "TotalMem": round(memory.total / 1024 / 1024, 2),  # MB
            "memNum": round(memory.percent, 2),
            "maxTaskNum": config.max_task_num,
            "state": 1,  # 1运行中 2暂停 3未连接
            "version": config.version,
        }
    
    def register_first_time(self):
        """首次注册节点"""
        try:
            redis_client = self.connection_manager.redis
            if not redis_client:
                raise RuntimeError("Redis connection not available")
            
            node_key = f"node:{config.node_name}"
            node_info = self._get_system_info()
            
            # 添加模块配置信息
            modules_config = {
                "MaxGoroutineCount": config.max_task_num,
                "SubdomainScan": {"GoroutineCount": 5},
                "PortScan": {"GoroutineCount": 5},
                "DirScan": {"GoroutineCount": 3},
                "VulnerabilityScan": {"GoroutineCount": 3},
            }
            node_info["modulesConfig"] = json.dumps(modules_config, ensure_ascii=False)
            
            redis_client.hmset(node_key, node_info)
            logger.info(f"Node registered successfully: {config.node_name} - version {config.version}")
            return True
        except Exception as e:
            logger.error(f"Failed to register node: {e}")
            return False
    
    def update_status(self):
        """更新节点状态"""
        try:
            redis_client = self.connection_manager.redis
            if not redis_client:
                raise RuntimeError("Redis connection not available")
            
            node_key = f"node:{config.node_name}"
            node_info = self._get_system_info()
            
            redis_client.hmset(node_key, node_info)
            logger.debug_local(f"Node status updated: {config.node_name}")
            return True
        except Exception as e:
            logger.error_local(f"Failed to update node status: {e}")
            return False
    
    def start_task(self):
        """开始任务"""
        self.running_tasks += 1
        logger.info(f"Task started. Running tasks: {self.running_tasks}")
    
    def end_task(self):
        """结束任务"""
        self.running_tasks = max(0, self.running_tasks - 1)
        self.finished_tasks += 1
        logger.info(f"Task finished. Running: {self.running_tasks}, Finished: {self.finished_tasks}")
    
    async def run_register_loop(self):
        """运行注册循环"""
        self.is_running = True
        first_register = True
        
        while self.is_running:
            try:
                if first_register:
                    if self.register_first_time():
                        first_register = False
                else:
                    self.update_status()
                
                # 每20秒更新一次
                await asyncio.sleep(20)
                
            except Exception as e:
                logger.error(f"Error in register loop: {e}")
                await asyncio.sleep(5)
    
    def stop(self):
        """停止注册循环"""
        self.is_running = False
        logger.info("Node registration stopped")

# 全局节点管理实例
node_manager = NodeManager() 