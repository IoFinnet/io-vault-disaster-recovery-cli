all: build

build: build-win build-mac build-linux-amd64 build-linux-arm64

build-win:
	GOOS=windows GOARCH=amd64 go build -trimpath -o ./bin/recovery-tool.exe ./

build-mac:
	GOOS=darwin GOARCH=arm64 go build -trimpath -o ./bin/recovery-tool-mac ./

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -trimpath -o ./bin/recovery-tool-linux-amd64 ./

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -trimpath -o ./bin/recovery-tool-linux-arm64 ./

build-linux: build-linux-amd64 build-linux-arm64

sandbox:
	sh ./try-sandbox.sh

test:
	go test -race ./...

.PHONY: build build-win build-linux-amd64 build-linux-arm64 build-linux build-mac sandbox test

