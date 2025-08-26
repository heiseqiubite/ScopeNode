#!/usr/bin/env python3
"""
Gogo扫描结果处理器
专门处理gogo扫描工具的结果格式
"""

import json
from typing import List, Dict, Any
from datetime import datetime
from pymongo import UpdateOne
from .base import BaseResultProcessor


class GogoResultProcessor(BaseResultProcessor):
    """Gogo扫描结果处理器"""
    
    def __init__(self, connection_manager=None):
        super().__init__(connection_manager)
        self.name = "GogoResultProcessor"
        self.version = "1.0.0"
        self.description = "专门处理Gogo扫描工具的结果格式"
        self.supported_formats = ['gogo_json']
    
    def validate_results(self, results: List[Dict]) -> bool:
        """验证是否为gogo扫描结果格式"""
        if not results:
            return False
        
        # 检查是否包含gogo特有的字段
        sample_result = results[0] if results else {}
        gogo_fields = ['ip', 'port', 'protocol', 'host']
        
        return any(field in sample_result for field in gogo_fields)
    
    def extract_scan_technologies(self, frameworks: Dict) -> List[str]:
        """从frameworks中提取技术栈信息"""
        if not frameworks:
            return []
        
        technologies = []
        for name, detail in frameworks.items():
            if isinstance(detail, dict):
                version = detail.get("version", "")
                tech = f"{name}:{version}" if version else name
            else:
                tech = str(name)
            technologies.append(tech)
        
        return technologies
    
    async def process_results(self, results: List[Dict], task: Any) -> Dict[str, Any]:
        """处理gogo扫描结果并批量插入数据库"""
        if len(results) < 1:
            self.log_warning("没有有效结果需要处理")
            return {'assets': 0, 'vulnerabilities': 0}
        
        try:
            await self.ensure_connection()
            
            # 过滤出有效资产结果
            total_records = len(results)
            scan_results = [
                r for r in results
                if isinstance(r, dict) and (
                    ("ip" in r or "host" in r) and ("port" in r or "protocol" in r)
                )
            ]
            
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log_info(f"解析到记录 {total_records} 条，其中有效资产 {len(scan_results)} 条")
            
            # 从task中提取项目信息
            project = 'default'
            task_name = getattr(task, 'task_name', 'default')
            
            asset_ops = []
            vuln_ops = []
            
            for result in scan_results:
                # 跳过ICMP结果
                if result.get("port") == "icmp":
                    continue
                
                # 提取基础数据
                ip = result.get("ip", "")
                host = result.get("host", ip)
                port = str(result.get("port", ""))
                protocol = result.get("protocol", "http")
                url = f"{protocol}://{ip}:{port}"
                
                # 构建资产文档
                asset_doc = {
                    "project": project,
                    "taskName": task_name,
                    "rootDomain": host or ip,
                    "time": now,
                    "ip": ip,
                    "host": ip,
                    "port": port,
                    "url": url,
                    "type": protocol,
                    "service": protocol,
                    "statuscode": int(result.get("status", 0)) if str(result.get("status", "")).isdigit() else 0,
                    "title": result.get("title", ""),
                    "technologies": self.extract_scan_technologies(result.get("frameworks", {})),
                    "metadata": json.dumps(result.get("frameworks", {})),
                    "iconcontent": "",
                    "tags": [],
                    "screenshot": "",
                    "rawheaders": "",
                    "webServer": result.get("midware", "")
                }
                
                asset_ops.append(
                    UpdateOne(
                        {"ip": ip, "port": port, "project": project},
                        {"$set": asset_doc},
                        upsert=True
                    )
                )
                
                # 处理漏洞信息
                for vuln_name, vuln_detail in result.get("vulns", {}).items():
                    vuln_ops.append(
                        UpdateOne(
                            {"url": url, "vulname": vuln_name, "project": project},
                            {"$set": {
                                "project": project,
                                "taskName": task_name,
                                "rootDomain": host or ip,
                                "time": now,
                                "url": url,
                                "vulname": vuln_name,
                                "vulnid": "",
                                "matched": vuln_detail.get("payload", ""),
                                "request": str(vuln_detail.get("detail", "")),
                                "response": "",
                                "level": vuln_detail.get("severity", ""),
                                "status": 1,
                                "tags": []
                            }},
                            upsert=True
                        )
                    )
            
            # 批量处理资产和漏洞
            results_summary = {'assets': 0, 'vulnerabilities': 0}
            
            if asset_ops and self.connection_manager:
                asset_col = self.connection_manager.get_mongo_collection('asset')
                if asset_col is not None:
                    result = await asset_col.bulk_write(asset_ops, ordered=False)
                    results_summary['assets'] = result.upserted_count + result.modified_count
            
            if vuln_ops and self.connection_manager:
                vuln_col = self.connection_manager.get_mongo_collection('vulnerability')
                if vuln_col is not None:
                    result = await vuln_col.bulk_write(vuln_ops, ordered=False)
                    results_summary['vulnerabilities'] = result.upserted_count + result.modified_count
            
            if not asset_ops and not vuln_ops:
                self.log_info("无可写入的资产或漏洞记录，结束处理")
                return results_summary
            
            self.log_info(f"处理完成 {task.target}: 资产: {results_summary['assets']}条, 漏洞: {results_summary['vulnerabilities']}条")
            return results_summary
                
        except Exception as e:
            self.log_error(f"处理gogo扫描结果错误: {str(e)}")
            raise
    
    def extract_metadata(self, result: Dict) -> Dict[str, Any]:
        """从gogo结果中提取元数据"""
        metadata = {}
        
        # 提取技术栈信息
        if 'frameworks' in result:
            metadata['technologies'] = self.extract_scan_technologies(result['frameworks'])
            metadata['frameworks'] = result['frameworks']
        
        # 提取服务信息
        if 'midware' in result:
            metadata['webserver'] = result['midware']
        
        # 提取状态码
        if 'status' in result:
            metadata['status_code'] = result['status']
        
        # 提取标题
        if 'title' in result:
            metadata['title'] = result['title']
        
        return metadata
