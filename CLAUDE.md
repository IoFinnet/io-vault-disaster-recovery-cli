# Vault Disaster Recovery CLI Development Guide

## Build Commands
```bash
make               # Build all binaries (Windows, Mac, Linux)
make build-mac     # Build Mac binary
make build-win     # Build Windows binary
make build-linux   # Build Linux binary
make test          # Run tests with race detection
```

## Test Commands
```bash
go test -race ./...                                # Run all tests
go test -v -run TestName ./...                     # Run a specific test
```

## Code Style Guidelines
- **Imports**: Group by standard library, third-party, then local packages
- **Naming**: PascalCase for exported, camelCase for unexported; ALL_CAPS for constants
- **Error Handling**: Wrap errors with context, use "⚠" symbol for warnings
- **Memory Management**: Clear sensitive data (like keys) with `clear()` function
- **Testing**: Use testify, name tests as TestXxx_Yyy_Zzz
- **Formatting**: Follow standard Go formatting (gofmt)
- **Types**: Define clearly structured types in types.go
- **Documentation**: Document exported functions and complex logic

## Usage
```bash
./bin/recovery-tool-mac file1.json file2.json      # Basic usage
./bin/recovery-tool-mac -vault-id <id> file1.json  # With vault ID
```