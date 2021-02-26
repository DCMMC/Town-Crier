FROM python:3-alpine3.10
MAINTAINER DCMMC <xwt97294597@gmail.com>

RUN mkdir /app
WORKDIR /app

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories
RUN apk add musl-dev build-base
RUN python3 -m pip install -i https://mirrors.bfsu.edu.cn/pypi/web/simple Flask mysql-connector-python grpcio==1.26.0 web3
COPY tc_pb2_grpc.py tc_pb2.py load_balancer.py voting.py /app/
ADD flask_cert /app/flask_cert

EXPOSE 9001
EXPOSE 8000
CMD [ "python3", "./load_balancer.py" ]
