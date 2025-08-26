import asyncio
import json
import time
import psutil
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass, field
from .config import config
from .logger import logger
from .node import node_manager
from .scanner import ScannerEngine
from datetime import datetime
from .connections import connection_manager

@dataclass
class TaskOptions:
    id: str
    task_name: str
    target: str
    type: str
    subdomain_scan: list
    port_scan: list
    dir_scan: list
    vulnerability_scan: list
    parameters: dict
    # 添加任务元数据
    created_time: float = field(default_factory=time.time)
    retry_count: int = 0
    max_retries: int = 3

@dataclass  
class RunningTaskInfo:
    """运行中任务信息"""
    task: TaskOptions
    asyncio_task: asyncio.Task
    process_id: Optional[int] = None
    start_time: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)

class TaskManager:
    def __init__(self):
        self.connection_manager = connection_manager
        self.scanner_engine = ScannerEngine(self.connection_manager)
        self.is_running = False
        # 添加信号量来控制并发任务数量
        self.task_semaphore = asyncio.Semaphore(config.max_task_num)
        # 跟踪正在运行的任务（使用详细信息）
        self.running_tasks: Dict[str, RunningTaskInfo] = {}
        # 添加任务统计
        self.stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'retried_tasks': 0,
            'killed_tasks': 0
        }
        self._setup_redis()
    
    def _setup_redis(self):
        """设置Redis连接池"""
        try:
            # 使用连接池提高性能
            self.connection_manager.setup_redis(use_pool=True, max_connections=10)
            logger.info(f"TaskManager Redis connection pool established")
        except Exception as e:
            logger.error(f"Failed to setup Redis connection in TaskManager: {e}")
            raise
    
    def _parse_task(self, task_data: str) -> Optional[TaskOptions]:
        """解析任务数据"""
        try:
            data = json.loads(task_data)
            return TaskOptions(
                id=data.get('ID', ''),
                task_name=data.get('TaskName', ''),
                target=data.get('Target', ''),
                type=data.get('Type', 'default'),
                subdomain_scan=data.get('SubdomainScan', []),
                port_scan=data.get('PortScan', []),
                dir_scan=data.get('DirScan', []),
                vulnerability_scan=data.get('VulnerabilityScan', []),
                parameters=data.get('Parameters', {}),
                retry_count=data.get('retry_count', 0),
                max_retries=data.get('max_retries', 3)
            )
        except (json.JSONDecodeError, ValueError) as e:
            logger.error(f"Failed to parse task data: {e}")
            return None
    
    async def _retry_redis_operation(self, operation, *args, max_retries=3):
        """Redis操作重试机制"""
        return await self.connection_manager.retry_redis_operation(operation, *args, max_retries=max_retries)
    
    async def get_task(self) -> Optional[TaskOptions]:
        """从Redis获取任务"""
        try:
            task_queue = f"NodeTask:{config.node_name}"
            
            redis_client = self.connection_manager.redis
            if not redis_client:
                logger.error("Redis connection not available")
                return None
            
            # 检查是否有任务模板 - 使用重试机制
            exists = await self._retry_redis_operation(redis_client.exists, task_queue)
            if not exists:
                return None
            
            # 第一步：从NodeTask队列获取任务模板（包含扫描配置）
            task_template_data = await self._retry_redis_operation(redis_client.lpop, task_queue)
            if not task_template_data:
                return None
            
            logger.debug(f"Got task template: {task_template_data[:100]}...")  # 截断长日志
            
            # 解析任务模板
            try:
                task_template = json.loads(task_template_data)
                task_id = task_template.get('ID')
                if not task_id:
                    logger.error("Task template missing ID field")
                    return None
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse task template: {e}")
                return None
            
            # 第二步：从TaskInfo队列获取一个目标（TaskInfo是队列，支持多个目标）
            task_info_key = f"TaskInfo:{task_id}"
            task_target_data = await self._retry_redis_operation(redis_client.lpop, task_info_key)
            
            if not task_target_data:
                logger.info(f"No more targets available for task ID: {task_id}, task completed")
                return None
            
            logger.debug(f"Got target for task {task_id}: {task_target_data}")
            
            # task_target_data是字符串，直接作为目标使用
            target_string = task_target_data.strip()
            if not target_string:
                logger.error(f"Empty target string for task {task_id}")
                # 将模板放回队列，但要先检查是否还有其他目标
                remaining_targets = await self._retry_redis_operation(redis_client.llen, task_info_key)
                if remaining_targets > 0:
                    await self._retry_redis_operation(redis_client.lpush, task_queue, task_template_data)
                    logger.debug(f"Task template {task_id} returned to queue due to empty target")
                return None
            
            # 检查TaskInfo队列是否还有更多目标
            remaining_targets = await self._retry_redis_operation(redis_client.llen, task_info_key)
            if remaining_targets > 0:
                # 如果还有更多目标，将任务模板放回队列末尾，供后续使用
                await self._retry_redis_operation(redis_client.rpush, task_queue, task_template_data)
                logger.debug(f"Task template {task_id} returned to queue, {remaining_targets} targets remaining")
            else:
                logger.info(f"All targets processed for task template {task_id}, template consumed")
            
            # 合并任务模板和目标信息
            complete_task = {**task_template, "Target": target_string}
            
            # 解析完整任务信息
            task = self._parse_task(json.dumps(complete_task))
            if task:
                self.stats['total_tasks'] += 1
            return task
            
        except Exception as e:
            logger.error(f"Failed to get task: {e}")
            return None
    
    async def _report_progress(self, task: TaskOptions, stage: str, status: str = "start"):
        """报告任务进度到Redis"""
        try:
            progress_key = f"TaskInfo:progress:{task.id}:{task.target}"
            field_name = f"{stage}_{status}"
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            redis_client = self.connection_manager.redis
            if not redis_client:
                logger.warning("Redis connection not available for progress reporting")
                return
                
            # 记录进度信息到Redis
            await self._retry_redis_operation(
                redis_client.hset,
                progress_key,
                field_name,
                timestamp
            )
            
            # 如果是扫描开始，记录节点信息
            if stage == "scan" and status == "start":
                await self._retry_redis_operation(
                    redis_client.hset,
                    progress_key,
                    "node",
                    config.node_name
                )
            
            logger.debug(f"Progress reported: {progress_key} -> {field_name}: {timestamp}")
            
        except Exception as e:
            logger.error(f"Failed to report progress for task {task.id}: {e}")

    async def execute_task(self, task: TaskOptions):
        """执行任务"""
        task_key = f"{task.id}_{task.target}"
        
        # 使用信号量控制并发数量
        async with self.task_semaphore:
            try:
                logger.info(f"Task begin: {task.id} - {task.task_name} - {task.target} (Running: {len(self.running_tasks)}/{config.max_task_num})")
                node_manager.start_task()
                
                # 报告任务开始
                await self._report_progress(task, "scan", "start")
                
                # 由于gogo是综合扫描工具，统一报告为各阶段开始
                await self._report_progress(task, "VulnerabilityScan", "start")
                
                # 执行扫描并获取进程ID
                process_id = await self.scanner_engine.run_scan_with_pid(task)
                
                # 更新运行任务信息中的进程ID
                if task_key in self.running_tasks:
                    self.running_tasks[task_key].process_id = process_id
                    self.running_tasks[task_key].last_heartbeat = time.time()
                    logger.info(f"Task {task.id} running with PID: {process_id}")
                
                # 报告任务结束
                await self._report_progress(task, "VulnerabilityScan", "end")
                await self._report_progress(task, "scan", "end")
                
                logger.info(f"Task completed: {task.id} - {task.task_name}")
                self.stats['completed_tasks'] += 1
                
            except Exception as e:
                logger.error(f"Task execution failed: {task.id} - {e}")
                self.stats['failed_tasks'] += 1                
                await self._handle_task_failure(task, str(e))
            finally:
                # 清理运行任务记录
                if task_key in self.running_tasks:
                    del self.running_tasks[task_key]
                node_manager.end_task()
    
    async def _monitor_task_processes(self):
        """监控任务进程状态"""
        while self.is_running:
            try:
                current_time = time.time()
                tasks_to_remove = []
                
                for task_key, task_info in self.running_tasks.items():
                    if task_info.process_id:
                        try:
                            # 检查进程是否还在运行
                            process = psutil.Process(task_info.process_id)
                            if process.is_running():
                                # 更新心跳时间
                                task_info.last_heartbeat = current_time
                                
                                # 输出运行状态
                                runtime = current_time - task_info.start_time
                                if runtime > 300 and int(runtime) % 300 == 0:  # 每5分钟输出一次
                                    cpu_percent = process.cpu_percent()
                                    memory_mb = process.memory_info().rss / 1024 / 1024
                                    logger.info(f"Task {task_info.task.id} still running (PID: {task_info.process_id}, "
                                              f"Runtime: {runtime:.0f}s, CPU: {cpu_percent}%, Memory: {memory_mb:.1f}MB)")
                            else:
                                logger.warning(f"Process {task_info.process_id} for task {task_info.task.id} is not running")
                                tasks_to_remove.append(task_key)
                        except psutil.NoSuchProcess:
                            logger.warning(f"Process {task_info.process_id} for task {task_info.task.id} not found")
                            tasks_to_remove.append(task_key)
                        except Exception as e:
                            logger.error(f"Error monitoring process {task_info.process_id}: {e}")
                
                # 清理已结束的任务
                for task_key in tasks_to_remove:
                    if task_key in self.running_tasks:
                        del self.running_tasks[task_key]
                
                await asyncio.sleep(30)  # 每30秒检查一次
                
            except Exception as e:
                logger.error(f"Error in process monitoring: {e}")
                await asyncio.sleep(60)
    
    async def kill_task(self, task_id: str, target: str = None) -> bool:
        """根据任务ID杀死任务"""
        task_key = f"{task_id}_{target}" if target else None
        
        # 查找匹配的任务
        matching_tasks = []
        if task_key and task_key in self.running_tasks:
            matching_tasks.append((task_key, self.running_tasks[task_key]))
        else:
            # 模糊匹配
            for key, task_info in self.running_tasks.items():
                if task_info.task.id == task_id:
                    matching_tasks.append((key, task_info))
        
        killed_count = 0
        for task_key, task_info in matching_tasks:
            try:
                if task_info.process_id:
                    process = psutil.Process(task_info.process_id)
                    process.terminate()  # 优雅终止
                    
                    # 等待3秒，如果还没结束就强制杀死
                    await asyncio.sleep(3)
                    if process.is_running():
                        process.kill()
                    
                    logger.info(f"Killed task {task_info.task.id} (PID: {task_info.process_id})")
                    killed_count += 1
                    self.stats['killed_tasks'] += 1
                
                # 取消asyncio任务
                if not task_info.asyncio_task.done():
                    task_info.asyncio_task.cancel()
                
                # 清理记录
                del self.running_tasks[task_key]
                
            except psutil.NoSuchProcess:
                logger.warning(f"Process {task_info.process_id} already terminated")
            except Exception as e:
                logger.error(f"Failed to kill task {task_info.task.id}: {e}")
        
        return killed_count > 0
    
    async def _handle_task_failure(self, task: TaskOptions, error_reason: str):
        """处理任务失败，实现重试机制"""
        
        if task.retry_count < task.max_retries:
            task.retry_count += 1
            self.stats['retried_tasks'] += 1
            
            # 将任务重新放入队列进行重试
            retry_task_data = {
                'ID': task.id,
                'TaskName': task.task_name,
                'Type': task.type,
                'SubdomainScan': task.subdomain_scan,
                'PortScan': task.port_scan,
                'DirScan': task.dir_scan,
                'VulnerabilityScan': task.vulnerability_scan,
                'Parameters': task.parameters,
                'retry_count': task.retry_count,
                'max_retries': task.max_retries
            }
            
            # 将目标信息重新放回TaskInfo队列（作为字符串）
            task_info_key = f"TaskInfo:{task.id}"
            target_data = task.target
            
            try:
                redis_client = self.connection_manager.redis
                if not redis_client:
                    logger.error("Redis connection not available for task retry")
                    return
                    
                await self._retry_redis_operation(
                    redis_client.rpush, 
                    task_info_key, 
                    target_data
                )
                
                # 将任务模板重新放回NodeTask队列（延迟重试）
                task_queue = f"NodeTask:{config.node_name}"
                await asyncio.sleep(30)  # 延迟30秒重试
                await self._retry_redis_operation(
                    redis_client.rpush, 
                    task_queue, 
                    json.dumps(retry_task_data)
                )
                
                logger.info(f"Task {task.id} scheduled for retry ({task.retry_count}/{task.max_retries}) due to: {error_reason}")
            except Exception as e:
                logger.error(f"Failed to schedule retry for task {task.id}: {e}")
        else:
            logger.error(f"Task {task.id} failed permanently after {task.max_retries} retries")
    
    def _cleanup_finished_tasks(self):
        """清理已完成的任务"""
        tasks_to_remove = []
        for task_key, task_info in self.running_tasks.items():
            if task_info.asyncio_task.done():
                if task_info.asyncio_task.exception():
                    logger.error(f"Task {task_info.task.id} finished with exception: {task_info.asyncio_task.exception()}")
                tasks_to_remove.append(task_key)
        
        for task_key in tasks_to_remove:
            del self.running_tasks[task_key]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取任务统计信息"""
        running_tasks_info = []
        for task_info in self.running_tasks.values():
            running_tasks_info.append({
                'id': task_info.task.id,
                'target': task_info.task.target,
                'pid': task_info.process_id,
                'runtime': time.time() - task_info.start_time
            })
        
        return {
            **self.stats,
            'running_tasks_count': len(self.running_tasks),
            'running_tasks_detail': running_tasks_info,
            'max_concurrent_tasks': config.max_task_num,
            'success_rate': (self.stats['completed_tasks'] / max(self.stats['total_tasks'], 1)) * 100
        }
    
    async def run_task_loop(self):
        """运行任务监听循环"""
        self.is_running = True
        logger.info(f"Task manager started with max concurrent tasks: {config.max_task_num}")
        
        # 启动进程监控任务
        monitor_task = asyncio.create_task(self._monitor_task_processes())
        
        # 定期打印统计信息
        last_stats_time = time.time()
        
        while self.is_running:
            try:
                # 清理已完成的任务
                self._cleanup_finished_tasks()
                
                # 定期打印统计信息（每5分钟）
                if time.time() - last_stats_time > 300:
                    stats = self.get_stats()
                    logger.info(f"Task stats: {stats}")
                    last_stats_time = time.time()
                
                # 每3秒检查一次任务
                await asyncio.sleep(3)
                
                # 只有在有可用槽位时才获取新任务
                if len(self.running_tasks) < config.max_task_num:
                    task = await self.get_task()
                    if task:
                        task_key = f"{task.id}_{task.target}"
                        # 创建新任务并跟踪它
                        new_task = asyncio.create_task(self.execute_task(task))
                        task_info = RunningTaskInfo(task=task, asyncio_task=new_task)
                        self.running_tasks[task_key] = task_info
                        logger.debug(f"Started new task {task.id}, running tasks: {len(self.running_tasks)}")
                
            except Exception as e:
                logger.error(f"Error in task loop: {e}")
                await asyncio.sleep(5)
        
        # 取消监控任务
        monitor_task.cancel()
    
    async def stop(self):
        """停止任务管理器"""
        self.is_running = False
        logger.info("Stopping task manager...")
        
        # 优雅地终止所有运行中的任务
        if self.running_tasks:
            logger.info(f"Gracefully stopping {len(self.running_tasks)} running tasks...")
            for task_key, task_info in self.running_tasks.items():
                if task_info.process_id:
                    try:
                        process = psutil.Process(task_info.process_id)
                        process.terminate()
                        logger.info(f"Sent SIGTERM to task {task_info.task.id} (PID: {task_info.process_id})")
                    except:
                        pass
            
            # 等待任务优雅退出（最多等待30秒）
            try:
                await asyncio.wait_for(
                    asyncio.gather(*[task_info.asyncio_task for task_info in self.running_tasks.values()], 
                                 return_exceptions=True),
                    timeout=30
                )
            except asyncio.TimeoutError:
                logger.warning("Timeout waiting for tasks to complete gracefully, force killing...")
                # 强制杀死剩余进程
                for task_info in self.running_tasks.values():
                    if task_info.process_id:
                        try:
                            process = psutil.Process(task_info.process_id)
                            process.kill()
                        except:
                            pass
        
        # 取消所有剩余的asyncio任务
        for task_info in self.running_tasks.values():
            if not task_info.asyncio_task.done():
                task_info.asyncio_task.cancel()
        
        # 关闭Redis连接
        self.connection_manager.close_redis()
        
        # 打印最终统计
        final_stats = self.get_stats()
        logger.info(f"Task manager stopped. Final stats: {final_stats}")
    
    async def _cleanup_progress(self, task: TaskOptions):
        """清理任务进度信息（可选）"""
        try:
            redis_client = self.connection_manager.redis
            if not redis_client:
                return
                
            progress_key = f"TaskInfo:progress:{task.id}:{task.target}"
            await self._retry_redis_operation(redis_client.delete, progress_key)
            logger.debug(f"Progress cleaned up for task {task.id}:{task.target}")
        except Exception as e:
            logger.error(f"Failed to cleanup progress for task {task.id}: {e}")
    
    async def get_task_progress(self, task_id: str, target: str) -> Dict[str, Any]:
        """查询任务进度"""
        try:
            redis_client = self.connection_manager.redis
            if not redis_client:
                return {}
                
            progress_key = f"TaskInfo:progress:{task_id}:{target}"
            progress_data = await self._retry_redis_operation(redis_client.hgetall, progress_key)
            return progress_data if progress_data else {}
        except Exception as e:
            logger.error(f"Failed to get progress for task {task_id}:{target}: {e}")
            return {}

# 全局任务管理实例
task_manager = TaskManager() 