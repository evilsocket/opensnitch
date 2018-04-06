all: ../daemon/ui/protocol/ui.pb.go ../ui/ui_pb2.py

../daemon/ui/protocol/ui.pb.go:
	protoc -I. ui.proto --go_out=plugins=grpc:../daemon/ui/protocol/

../ui/ui_pb2.py:
	python -m grpc_tools.protoc -I. --python_out=../ui/ --grpc_python_out=../ui/ ui.proto

clean:
	@rm -rf ../daemon/ui/protocol/ui.pb.go
	@rm -rf ../ui/ui_pb2.py
	@rm -rf ../ui/ui_pb2_grpc.py
