#!/usr/bin/env python3
"""
Gogo扫描器插件
重构原有的gogo扫描功能为插件形式
"""

import asyncio
import subprocess
import os
import time
import json
import zlib
import logging
from typing import Dict, List, Optional
from .base import BaseScannerPlugin, ScanResult


class GogoScannerPlugin(BaseScannerPlugin):
    """Gogo综合扫描器插件"""
    
    def __init__(self):
        super().__init__()
        self.name = "GogoScanner"
        self.version = "1.0.0"
        self.description = "Gogo综合安全扫描工具插件"
        self.supported_targets = ['url', 'ip', 'domain', 'cidr']
        self.result_processor_type = 'gogo'  # 使用gogo专用的结果处理器
        self.tools_path = "tools"
        self._ensure_tools_directory()
        self._check_gogo_availability()
    
    def _ensure_tools_directory(self):
        """确保工具目录存在"""
        if not os.path.exists(self.tools_path):
            os.makedirs(self.tools_path)
    
    def _check_gogo_availability(self):
        """检查gogo工具是否可用"""
        try:
            result = subprocess.run(['tools/gogo', '-h'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logging.getLogger('scanner').info("Gogo tool is available")
            else:
                logging.getLogger('scanner').warning("Gogo tool check returned non-zero exit code")
        except FileNotFoundError:
            logging.getLogger('scanner').error("Gogo tool not found! Please install gogo first.")
        except subprocess.TimeoutExpired:
            logging.getLogger('scanner').warning("Gogo tool check timeout")
        except Exception as e:
            logging.getLogger('scanner').error(f"Failed to check gogo availability: {e}")
    
    def validate_task(self, task) -> bool:
        """验证任务是否适用于gogo扫描器"""
        # 检查目标是否存在
        if not hasattr(task, 'target') or not task.target:
            return False
        
        # 检查是否有扫描参数
        if hasattr(task, 'parameters') and task.parameters:
            # 检查是否有漏洞扫描参数
            vuln_scan_params = task.parameters.get('VulnerabilityScan', {})
            if vuln_scan_params:
                return True
        
        # 检查任务类型中是否包含漏洞扫描
        if hasattr(task, 'vulnerability_scan') and task.vulnerability_scan:
            return True
        
        # 默认允许所有任务（使用默认扫描参数）
        return True
    
    def get_command_template(self) -> str:
        """获取gogo命令模板"""
        return "tools/gogo -i {target} -f {output_file} {additional_args}"
    
    def _build_gogo_command(self, target: str, parameters: Dict, output_file: str) -> List[str]:
        """构建gogo命令"""
        command = ["tools\\gogo", "-i"]
        command.append(target)
        
        # 添加输出文件参数
        command.extend(["-f", output_file])
        
        # 获取VulnerabilityScan参数
        vuln_scan_params = parameters.get('VulnerabilityScan', {})
        
        # 查找第一个非空的扫描参数
        command_args = None
        for scan_id, args in vuln_scan_params.items():
            if args and isinstance(args, str) and args.strip():
                command_args = args.strip()
                logging.getLogger('scanner').info(f"Using vulnerability scan parameters from {scan_id}: {command_args}")
                break
        
        if command_args:
            # 使用找到的扫描参数
            command.extend(command_args.split())
        else:
            # 回退：如果没有找到有效参数，使用默认的综合扫描
            logging.getLogger('scanner').warning("No valid vulnerability scan parameters found, using default comprehensive scan")
            command.extend(["-p", "all", "-e", "-v"])
        
        return command
    
    async def scan(self, task, progress_callback=None) -> ScanResult:
        """执行gogo扫描"""
        start_time = time.time()
        target = task.target
        
        try:
            logging.getLogger('scanner').info(f"Starting gogo scan for target: {target}")
            
            # 生成输出文件名
            timestamp = int(time.time())
            output_file = f"scan_results_{target.replace(':', '_').replace('/', '_')}_{timestamp}.dat"
            output_path = os.path.join(self.tools_path, output_file)
            
            # 构建gogo命令
            parameters = getattr(task, 'parameters', {})
            command = self._build_gogo_command(target, parameters, output_path)
            logging.getLogger('scanner').info(f"Executing: {' '.join(command)}")
            
            # 报告扫描开始
            if progress_callback:
                await progress_callback("scan", "start")
                await progress_callback("VulnerabilityScan", "start")
            
            # 启动进程
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            logging.getLogger('scanner').info(f"Gogo process started with PID: {process.pid}")
            
            # 等待进程完成
            stdout, stderr = await process.communicate()
            stdout_text = stdout.decode('utf-8', errors='ignore') if stdout else ""
            stderr_text = stderr.decode('utf-8', errors='ignore') if stderr else ""
            
            execution_time = time.time() - start_time
            
            if process.returncode == 0:
                logging.getLogger('scanner').info(f"Gogo scan completed for {target} in {execution_time:.2f}s")
                
                # 解析结果文件
                scan_results = []
                if os.path.exists(output_path):
                    logging.getLogger('scanner').info(f"Scan results saved to file: {output_path}")
                    scan_results = await self._parse_results_file(output_path)
                    
                    # 清理临时文件
                    try:
                        os.remove(output_path)
                        logging.getLogger('scanner').info(f"Cleaned up temporary scan file: {output_path}")
                    except Exception as e:
                        logging.getLogger('scanner').warning(f"Failed to clean up scan file {output_path}: {e}")
                
                # 报告扫描结束
                if progress_callback:
                    await progress_callback("VulnerabilityScan", "end")
                    await progress_callback("scan", "end")
                
                return ScanResult(
                    target=target,
                    scanner_type="gogo",
                    success=True,
                    results=scan_results,
                    metadata={
                        'execution_time': execution_time,
                        'process_id': process.pid,
                        'command': ' '.join(command),
                        'stdout_preview': stdout_text[:500] if stdout_text else "",
                        'result_count': len(scan_results)
                    }
                )
            else:
                error_msg = f"Gogo scan failed: {stderr_text}"
                logging.getLogger('scanner').error(error_msg)
                
                return ScanResult(
                    target=target,
                    scanner_type="gogo",
                    success=False,
                    results=[],
                    error_message=error_msg,
                    metadata={
                        'execution_time': execution_time,
                        'process_id': process.pid,
                        'command': ' '.join(command),
                        'return_code': process.returncode,
                        'stderr': stderr_text
                    }
                )
                
        except Exception as e:
            error_msg = f"Gogo scan failed for target {target}: {e}"
            logging.getLogger('scanner').error(error_msg)
            
            return ScanResult(
                target=target,
                scanner_type="gogo",
                success=False,
                results=[],
                error_message=error_msg,
                metadata={
                    'execution_time': time.time() - start_time,
                    'exception': str(e)
                }
            )
    
    async def _parse_results_file(self, file_path: str) -> List[Dict]:
        """解析gogo结果文件"""
        try:
            # 读取结果文件
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # 使用zlib解压缩
            flatedict = bytes(', ":'.encode())
            content = zlib.decompressobj(-15, zdict=flatedict).decompress(content).decode()
            
            # 解析JSON行
            results = []
            for line in content.splitlines():
                if line.strip():
                    try:
                        result = json.loads(line)
                        results.append(result)
                    except json.JSONDecodeError as e:
                        logging.getLogger('scanner').warning(f"Failed to parse JSON line: {line[:100]}... - {e}")
            
            logging.getLogger('scanner').info(f"Parsed {len(results)} results from file {file_path}")
            return results
            
        except Exception as e:
            logging.getLogger('scanner').error(f"Failed to parse results file {file_path}: {e}")
            return []
