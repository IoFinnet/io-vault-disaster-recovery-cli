all: build

build:
	go build -o ./bin/recovery-tool ./ && chmod +x ./bin/*

build-win:
	GOOS=windows GOARCH=amd64 go build -o ./bin/recovery-tool.exe ./

sandbox:
	sh ./try-sandbox.sh
