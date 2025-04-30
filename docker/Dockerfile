# syntax=docker/dockerfile:1

FROM registry.cn-hangzhou.aliyuncs.com/fengmuxi-docker-images/docker.io_python:3.8-slim-buster

LABEL maintainer="tongdongdong@outlook.com"

# Keeps Python from generating .pyc files in the container
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

WORKDIR /cf2dns

COPY . /cf2dns

# 安装requirements.txt中指定的任何所需包
# RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple some-package
# Install pip requirements
RUN python -m pip install --no-cache-dir --upgrade -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/


# Creates a non-root user with an explicit UID and adds permission to access the /app folder
#RUN adduser -u 5678 --disabled-password --gecos "" appuser && chown -R appuser /app
#USER appuser

CMD ["python3", "src/main.py"]
