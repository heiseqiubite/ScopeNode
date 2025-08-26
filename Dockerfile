FROM python:3.11-slim

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/opt/python_scanner

# 更新包列表并安装必要的包
RUN apt-get update && \
    apt-get install -y \
        git \
        curl \
        ca-certificates \
        libcurl4-openssl-dev \
        vim \
        unzip \
        wget \
        gcc \
        g++ \
        make \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /opt/python_node

# 首先复制requirements.txt以利用Docker缓存
COPY ./python_node /opt/python_node

# 安装Python依赖包
RUN pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple --no-cache-dir

# 启动命令
CMD ["python", "run.py"]