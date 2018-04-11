all: ../daemon/ui/protocol/ui.pb.go ../ui/ui_pb2.py

../daemon/ui/protocol/ui.pb.go:
	protoc -I. ui.proto --go_out=plugins=grpc:../daemon/ui/protocol/

../ui/ui_pb2.py:
	python3 -m grpc_tools.protoc -I. --python_out=../ui/opensnitch/ --grpc_python_out=../ui/opensnitch/ ui.proto

clean:
	@rm -rf ../daemon/ui/protocol/ui.pb.go
	@rm -rf ../ui/opensnitch/ui_pb2.py
	@rm -rf ../ui/opensnitch/ui_pb2_grpc.py
