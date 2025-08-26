"""
结果处理器模块
每个扫描器插件可以有自己的结果处理器
"""

from .base import BaseResultProcessor
from .gogo_processor import GogoResultProcessor

# 可用的结果处理器
AVAILABLE_PROCESSORS = {
    'gogo': GogoResultProcessor,
    # 未来可以添加更多处理器
    # 'nmap': NmapResultProcessor,
    # 'nuclei': NucleiResultProcessor,
}

def get_result_processor(processor_type: str, connection_manager=None) -> BaseResultProcessor:
    """根据类型获取结果处理器实例"""
    if processor_type not in AVAILABLE_PROCESSORS:
        raise ValueError(f"Unknown processor type: {processor_type}. Available: {list(AVAILABLE_PROCESSORS.keys())}")
    
    return AVAILABLE_PROCESSORS[processor_type](connection_manager)

__all__ = ['BaseResultProcessor', 'GogoResultProcessor', 'get_result_processor', 'AVAILABLE_PROCESSORS']
