#!/usr/bin/env python3
"""
统一连接管理器
负责管理Redis和MongoDB连接，避免重复连接创建
"""

import asyncio
import redis
import logging
from typing import Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorClient
from .config import config


class ConnectionManager:
    """统一连接管理器，使用单例模式"""
    
    _instance: Optional['ConnectionManager'] = None
    _initialized: bool = False
    
    def __new__(cls) -> 'ConnectionManager':
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._redis_client: Optional[redis.Redis] = None
        self._redis_pool: Optional[redis.ConnectionPool] = None
        self._mongo_client: Optional[AsyncIOMotorClient] = None
        self._mongo_db = None
        self._redis_connected: bool = False
        self._mongo_connected: bool = False
        self._initialized = True
    
    def setup_redis(self, use_pool: bool = True, max_connections: int = 10) -> redis.Redis:
        """设置Redis连接"""
        if self._redis_connected and self._redis_client:
            return self._redis_client
        
        try:
            if use_pool:
                # 使用连接池
                self._redis_pool = redis.ConnectionPool(
                    host=config.redis.host,
                    port=config.redis.port,
                    password=config.redis.password,
                    decode_responses=True,
                    max_connections=max_connections,
                    retry_on_timeout=True
                )
                self._redis_client = redis.Redis(connection_pool=self._redis_pool)
            else:
                # 简单连接
                self._redis_client = redis.Redis(
                    host=config.redis.host,
                    port=config.redis.port,
                    password=config.redis.password,
                    decode_responses=True
                )
            
            # 测试连接
            self._redis_client.ping()
            self._redis_connected = True
            logging.getLogger('scanner').info(f"Redis connection established: {config.redis.host}:{config.redis.port} (pool: {use_pool})")
            return self._redis_client
            
        except Exception as e:
            logging.getLogger('scanner').error(f"Failed to connect to Redis: {e}")
            self._redis_client = None
            self._redis_connected = False
            raise
    
    async def setup_mongo(self) -> AsyncIOMotorClient:
        """设置MongoDB连接"""
        if self._mongo_connected and self._mongo_client is not None:
            return self._mongo_client
        
        try:
            host = config.mongodb.host
            port = config.mongodb.port
            username = (config.mongodb.username or '').strip()
            password = (config.mongodb.password or '').strip()

            if username:
                uri = f"mongodb://{username}:{password}@{host}:{port}/"
            else:
                uri = f"mongodb://{host}:{port}/"

            self._mongo_client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=3000)
            self._mongo_db = self._mongo_client[config.mongodb.database or 'scope_sentry']

            # 测试连接
            await self._mongo_db.command('ping')
            self._mongo_connected = True
            logging.getLogger('scanner').info(f"MongoDB connection established: {config.mongodb.host}:{config.mongodb.port}")
            return self._mongo_client
            
        except Exception as e:
            logging.getLogger('scanner').error(f"MongoDB connection failed: {e}")
            self._mongo_client = None
            self._mongo_db = None
            self._mongo_connected = False
            raise
    
    @property
    def redis(self) -> Optional[redis.Redis]:
        """获取Redis客户端"""
        if not self._redis_connected:
            try:
                return self.setup_redis()
            except Exception:
                return None
        return self._redis_client
    
    @property
    def mongo_client(self) -> Optional[AsyncIOMotorClient]:
        """获取MongoDB客户端"""
        return self._mongo_client
    
    @property
    def mongo_db(self):
        """获取MongoDB数据库"""
        return self._mongo_db
    
    async def ensure_mongo_connected(self):
        """确保MongoDB已连接"""
        if not self._mongo_connected:
            await self.setup_mongo()
    
    def ensure_redis_connected(self):
        """确保Redis已连接"""
        if not self._redis_connected:
            self.setup_redis()
    
    async def retry_redis_operation(self, operation, *args, max_retries: int = 3):
        """Redis操作重试机制"""
        for attempt in range(max_retries):
            try:
                if not self._redis_connected:
                    self.setup_redis()
                return await asyncio.get_event_loop().run_in_executor(None, operation, *args)
            except (redis.ConnectionError, redis.TimeoutError) as e:
                if attempt == max_retries - 1:
                    logging.getLogger('scanner').error(f"Redis operation failed after {max_retries} attempts: {e}")
                    raise
                logging.getLogger('scanner').warning(f"Redis operation failed, retrying... (attempt {attempt + 1}/{max_retries})")
                await asyncio.sleep(1 * (attempt + 1))  # 指数退避
                # 重新连接
                self._redis_connected = False
                self._redis_client = None
    
    def get_mongo_collection(self, collection_name: str):
        """获取MongoDB集合"""
        if self._mongo_db is None:
            return None
        return self._mongo_db[collection_name]
    
    def close_redis(self):
        """关闭Redis连接"""
        if self._redis_pool:
            self._redis_pool.disconnect()
        self._redis_client = None
        self._redis_connected = False
        logging.getLogger('scanner').info("Redis connection closed")
    
    async def close_mongo(self):
        """关闭MongoDB连接"""
        if self._mongo_client is not None:
            self._mongo_client.close()
            self._mongo_client = None
            self._mongo_db = None
            self._mongo_connected = False
            logging.getLogger('scanner').info("MongoDB connection closed")
    
    async def close_all(self):
        """关闭所有连接"""
        self.close_redis()
        await self.close_mongo()
    
    def get_status(self) -> Dict[str, Any]:
        """获取连接状态"""
        return {
            'redis_connected': self._redis_connected,
            'mongo_connected': self._mongo_connected,
            'redis_host': f"{config.redis.host}:{config.redis.port}",
            'mongo_host': f"{config.mongodb.host}:{config.mongodb.port}",
            'mongo_database': config.mongodb.database
        }


# 全局连接管理器实例
connection_manager = ConnectionManager()
