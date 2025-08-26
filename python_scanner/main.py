#!/usr/bin/env python3
"""
Python Scanner - ScopeSentry扫描节点
基于ScopeSentry-Scan项目的Python实现

功能:
1. 节点注册 - 向Redis注册节点信息
2. 任务监听 - 从Redis队列获取扫描任务  
3. Gogo扫描 - 执行各种扫描工具包括gogo
"""

import asyncio
import signal
import sys
from typing import List
from .config import config
from .logger import logger
from .node import node_manager
from .task_manager import task_manager
from .connections import connection_manager

class ScannerApp:
    def __init__(self):
        self.running = False
        self.tasks: List[asyncio.Task] = []
        self.shutdown_event = asyncio.Event()
    
    def _signal_handler(self, sig, frame):
        """信号处理器"""
        logger.info(f"Received signal {sig}, shutting down...")
        # 设置shutdown事件，让主循环处理异步停止
        asyncio.create_task(self._trigger_shutdown())
    
    async def _trigger_shutdown(self):
        """触发异步停止"""
        self.shutdown_event.set()
    
    def _setup_signal_handlers(self):
        """设置信号处理器"""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    async def start(self):
        """启动扫描器"""
        try:
            logger.info("Starting Python Scanner...")
            logger.info(f"Node Name: {config.node_name}")
            logger.info(f"Version: {config.version}")
            logger.info(f"Redis: {config.redis.host}:{config.redis.port}")
            logger.info(f"Mongodb: {config.mongodb.host}:{config.mongodb.port}")
            
            # 初始化连接
            await connection_manager.setup_mongo()
            
            self.running = True
            
            # 启动节点注册任务
            node_task = asyncio.create_task(node_manager.run_register_loop())
            self.tasks.append(node_task)
            
            # 启动任务监听任务
            task_task = asyncio.create_task(task_manager.run_task_loop())
            self.tasks.append(task_task)
            
            # 启动shutdown监听任务
            shutdown_task = asyncio.create_task(self._wait_for_shutdown())
            self.tasks.append(shutdown_task)
            
            logger.info("Scanner started successfully")
            
            # 等待所有任务完成
            await asyncio.gather(*self.tasks, return_exceptions=True)
            
        except Exception as e:
            logger.error(f"Failed to start scanner: {e}")
            sys.exit(1)
    
    async def _wait_for_shutdown(self):
        """等待shutdown事件"""
        await self.shutdown_event.wait()
        await self.stop()
    
    async def stop(self):
        """停止扫描器"""
        if not self.running:
            return
        
        self.running = False
        logger.info("Stopping scanner...")
        
        # 停止各个组件（task_manager的stop现在是异步的）
        node_manager.stop()
        await task_manager.stop()
        
        # 关闭所有连接
        await connection_manager.close_all()
        
        # 取消所有任务
        for task in self.tasks:
            if not task.done():
                task.cancel()
        
        logger.info("Scanner stopped")

def print_banner():
    """打印Banner"""
    banner = """
   ____        _   _                   ____                                  
  |  _ \ _   _| |_| |__   ___  _ __   / ___|  ___ __ _ _ __  _ __   ___ _ __   
  | |_) | | | | __| '_ \ / _ \| '_ \  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|  
  |  __/| |_| | |_| | | | (_) | | | |  ___) | (_| (_| | | | | | | |  __/ |     
  |_|    \__, |\__|_| |_|\___/|_| |_| |____/ \___\__,_|_| |_|_| |_|\___|_|     
         |___/                                                                
    """
    print(banner)
    print("Python Scanner - ScopeSentry扫描节点")
    print("版本: 1.0.0")
    print("-" * 70)

async def main():
    """主函数"""
    print_banner()
    
    app = ScannerApp()
    app._setup_signal_handlers()
    
    try:
        await app.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        await app.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram interrupted by user")
        sys.exit(0) 