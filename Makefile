FILES             ?= $(shell find . -type f -name '*.go')

all: deps build

format:
	@echo ">> formatting code"
	@goimports -w $(FILES)

deps: install-tools
	@echo ">> downloading dependencies"
	@go mod download

build:
	@echo ">> compiling oidc"
	@go build ./...

install-tools:
	@echo ">> fetching goimports"
	@go get -u golang.org/x/tools/cmd/goimports

test: build
	@echo ">> running all tests"
	@go test $(shell go list ./...)

.PHONY: all format deps build install-tools test
