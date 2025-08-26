"""
扫描器插件模块
"""

from .base import BaseScannerPlugin
from .gogo_scanner import GogoScannerPlugin

# 可用的扫描器插件
AVAILABLE_SCANNERS = {
    'gogo': GogoScannerPlugin,
    # 未来可以添加更多扫描器
    # 'nmap': NmapScannerPlugin,
    # 'nuclei': NucleiScannerPlugin,
}

def get_scanner_plugin(scanner_type: str) -> BaseScannerPlugin:
    """根据类型获取扫描器插件实例"""
    if scanner_type not in AVAILABLE_SCANNERS:
        raise ValueError(f"Unknown scanner type: {scanner_type}. Available: {list(AVAILABLE_SCANNERS.keys())}")
    
    return AVAILABLE_SCANNERS[scanner_type]()

__all__ = ['BaseScannerPlugin', 'GogoScannerPlugin', 'get_scanner_plugin', 'AVAILABLE_SCANNERS']
