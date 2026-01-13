# Version 32 enabled edition 2024
# https://github.com/protocolbuffers/protobuf/releases/tag/v32.0
PROTOC_MIN_2024 := 32
PROTOC_MAJOR_VER ?= $(shell python3 -m grpc_tools.protoc --version | cut -d' ' -f2 | cut -d. -f1)

ifeq ($(shell [ $(PROTOC_MAJOR_VER) -ge $(PROTOC_MIN_2024) ] && echo pass),pass)
	EXPERIMENTAL_EDITIONS := --experimental_editions
else
	EXPERIMENTAL_EDITIONS :=
endif

all: ../daemon/ui/protocol/ui.pb.go ../ui/opensnitch/ui_pb2.py

../daemon/ui/protocol/ui.pb.go: ui.proto
	protoc -I. ui.proto --go_out=../daemon/ui/protocol/ --go-grpc_out=../daemon/ui/protocol/ --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative

../ui/opensnitch/ui_pb2.py: ui.proto
	python3 -m grpc_tools.protoc $(EXPERIMENTAL_EDITIONS) -I. --python_out=../ui/opensnitch/proto/ --grpc_python_out=../ui/opensnitch/proto/ ui.proto

clean:
	@rm -rf ../daemon/ui/protocol/ui.pb.go
	@rm -rf ../daemon/ui/protocol/ui_grpc.pb.go
	@rm -rf ../ui/opensnitch/proto/ui_pb2.py
	@rm -rf ../ui/opensnitch/proto/ui_pb2_grpc.py
