all:
	protoc -I. ui.proto --go_out=plugins=grpc:.
	python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. ui.proto

clean:
	@rm -rf *.go
	@rm -rf *.py
