all: build

build:
	go build -o ./bin/recovery-tool ./ && chmod +x ./bin/*

build-win:
	GOOS=windows GOARCH=amd64 go build -o ./bin/recovery-tool.exe ./

build-mac:
	GOOS=darwin GOARCH=arm64 go build -o ./bin/recovery-tool.exe ./

build-linux:
	GOOS=linux GOARCH=amd64 go build -o ./bin/recovery-tool.exe ./

sandbox:
	sh ./try-sandbox.sh

.PHONY: build build-win build-linux build-mac sandbox

