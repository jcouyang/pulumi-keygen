# Makefile for pulumi-keygen provider

.PHONY: build install schema test

# Default target
all: build

# Build the provider binary
build:
	go build -o pulumi-resource-keygen .

# Generate schema
schema: build
	pulumi package get-schema ./pulumi-resource-keygen > schema.json

# Run tests
test:
	go test ./...

# Clean build artifacts
clean:
	rm -f pulumi-resource-keygen
	rm -f schema.json

sdk: build
	pulumi package gen-sdk --language nodejs ./pulumi-resource-keygen
	pulumi package gen-sdk --language go ./pulumi-resource-keygen
# Release build for different platforms
release:
	gh release v${VERSION} ./ubuntu-latest-binary/pulumi-resource-keygen-v${VERSION}-linux-amd64 ./macos-latest/pulumi-resource-keygen-v${VERSION}-darwin-amd64

release-linux:
	GOOS=linux GOARCH=amd64 go build -o dist/pulumi-resource-keygen-v${VERSION}-linux-amd64 .

release-darwin:
	GOOS=darwin GOARCH=amd64 go build -o dist/pulumi-resource-keygen-v${VERSION}-darwin-amd64 .

# Help
help:
	@echo "Available targets:"
	@echo "  build     - Build the provider binary"
	@echo "  install   - Install the provider binary to ~/.pulumi/plugins"
	@echo "  schema    - Generate schema.json"
	@echo "  test      - Run tests"
	@echo "  clean     - Clean build artifacts"
	@echo "  release   - Build release binaries for all platforms"
	@echo "  help      - Show this help message"
