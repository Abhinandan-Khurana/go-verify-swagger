# Makefile for building go-verify-swagger for multiple platforms

# Project name
BINARY_NAME=go-verify-swagger

# Source file
SRC_FILE=main.go

# Output directories
OUTPUT_DIR=dist

# Platforms and architectures
PLATFORMS=\
    darwin amd64 \
    darwin arm64 \
    linux amd64 \
    linux arm64 \
    windows amd64 \
    windows arm64

# Build command
build:
	mkdir -p $(OUTPUT_DIR)
	$(foreach platform_arch,$(PLATFORMS), \
		$(eval GOOS=$(word 1,$(subst _, ,$(platform_arch)))) \
		$(eval GOARCH=$(word 2,$(subst _, ,$(platform_arch)))) \
		echo "Building for $(GOOS)/$(GOARCH)..." \
		&& GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(OUTPUT_DIR)/$(BINARY_NAME)-$(GOOS)-$(GOARCH)$(if $(filter windows,$(GOOS)),.exe) $(SRC_FILE) \
	;)

# Clean build files
clean:
	rm -rf $(OUTPUT_DIR)

# Default target
all: clean build
