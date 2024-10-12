#!/bin/bash

# 停止并移除所有 Docker 容器
echo "Stopping and removing existing containers..."
docker-compose down

# 重新构建 Docker 镜像
echo "Building Docker images..."
docker-compose build

# 启动服务
echo "Starting services in detached mode..."
docker-compose up -d

echo "All done!"

