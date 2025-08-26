#!/usr/bin/env python3
"""
Python Scanner启动脚本
"""

import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from python_scanner.main import main
import asyncio

if __name__ == "__main__":
    asyncio.run(main()) 