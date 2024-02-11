##
#
# build using
#
# podman run --name go -v $PWD:/go --rm -it docker.io/library/golang:latest
# 
# switch to ansible to make universal might be harder
# 
apt update -y
apt install -y \
 golang \
 libqt5scripttools5 \
 pyqt5-dev-tools \
 python3-grpc-tools \
 protobuf-compiler-grpc \
 python3-pip \
 libnetfilter-queue-dev \
 python3.11-venv \
 qttools5-dev-tools
python3 -mvenv opensnitch
. ./opensnitch/bin/activate
python -m pip install -r ./ui/requirements.txt
go install google.golang.org/protobuf@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
make
