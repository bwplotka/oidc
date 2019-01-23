FILES             ?= $(shell find . -type f -name '*.go' -not -path "./vendor/*")

all: deps build

format:
	@echo ">> formatting code"
	@goimports -w $(FILES)

deps: install-tools
	@echo ">> downloading dependencies"
	@dep ensure

build:
	@echo ">> compiling oidc"
	@go build ./...

install-tools:
	@echo ">> fetching goimports"
	@go get -u golang.org/x/tools/cmd/goimports
	@echo ">> fetching dep"
	@go get -u github.com/golang/dep/cmd/dep

test: build
	@echo ">> running all tests"
	@go test $(shell go list ./... | grep -v /vendor/)

.PHONY: all format deps build install-tools test
