all: ../daemon/ui/protocol/ui.pb.go ../ui/opensnitch/ui_pb2.py

../daemon/ui/protocol/ui.pb.go: ui.proto
	# This assumes protoc-gen-go prior to v1.20.0, which you can get with
	# `go get github.com/golang/protobuf/protoc-gen-go` (and not with
	# `go get google.golang.org/protobuf/cmd/protoc-gen-go`)
	protoc -I. ui.proto --go_out=plugins=grpc,paths=source_relative:../daemon/ui/protocol/

../ui/opensnitch/ui_pb2.py: ui.proto
	python3 -m grpc_tools.protoc -I. --python_out=../ui/opensnitch/ --grpc_python_out=../ui/opensnitch/ ui.proto

clean:
	@rm -rf ../daemon/ui/protocol/ui.pb.go
	@rm -rf ../ui/opensnitch/ui_pb2.py
	@rm -rf ../ui/opensnitch/ui_pb2_grpc.py
