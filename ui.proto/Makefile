all:
	protoc -I. ui.proto --go_out=plugins=grpc:.

clean:
	@rm -rf ui.pb.go
