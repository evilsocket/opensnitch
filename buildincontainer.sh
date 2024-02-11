go install google.golang.org/protobuf@3.20.x
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
export PATH=$PWD/bin:$PATH
make
