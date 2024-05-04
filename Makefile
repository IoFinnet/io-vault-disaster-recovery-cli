all: build

build: build-win build-mac build-linux

build-win:
	GOOS=windows GOARCH=amd64 go build -trimpath -o ./bin/recovery-tool.exe ./

build-mac:
	GOOS=darwin GOARCH=arm64 go build -trimpath -o ./bin/recovery-tool-mac ./

build-linux:
	GOOS=linux GOARCH=amd64 go build -trimpath -o ./bin/recovery-tool-linux ./

sandbox:
	sh ./try-sandbox.sh

.PHONY: build build-win build-linux build-mac sandbox

