all: ../daemon/ui/protocol/ui.pb.go ../ui/opensnitch/ui_pb2.py

../daemon/ui/protocol/ui.pb.go: ui.proto
	protoc -I. ui.proto --go_out=../daemon/ui/protocol/ --go-grpc_out=../daemon/ui/protocol/ --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative

../ui/opensnitch/ui_pb2.py: ui.proto
	python3 -m grpc_tools.protoc --experimental_editions -I. --python_out=../ui/opensnitch/proto/ --grpc_python_out=../ui/opensnitch/proto/ ui.proto

clean:
	@rm -rf ../daemon/ui/protocol/ui.pb.go
	@rm -rf ../daemon/ui/protocol/ui_grpc.pb.go
	@rm -rf ../ui/opensnitch/proto/ui_pb2.py
	@rm -rf ../ui/opensnitch/proto/ui_pb2_grpc.py
