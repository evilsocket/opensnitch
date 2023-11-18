# podman run --name go -v $PWD:/go --rm -it
FROM docker.io/ubuntu:23.10
RUN apt update -y && apt install -y \
 less \
 vim \
 golang \
 libqt5scripttools5 \
 pyqt5-dev-tools \
 python3-grpc-tools \
 protobuf-compiler-grpc \
 python3-pip \
 libnetfilter-queue-dev \
 python3.11-venv \
 qttools5-dev-tools
COPY ui/requirements.txt /tmp/requirements.txt
RUN python3 -m pip install -r /tmp/requirements.txt --break-system-packages
WORKDIR /go
