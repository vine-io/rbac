NAME=$(shell echo "rbac")
PROTODIR=$(shell go env GOPATH)
DIR=$(shell pwd)
PACKAGE=github.com/vine-io/rbac
GIT_COMMIT=$(shell git rev-parse --short HEAD)
GIT_TAG=$(shell git describe --abbrev=0 --tags --always --match "v*")
GIT_VERSION=github.com/vine-io/rbac/pkg/internal/doc
CGO_ENABLED=0
BUILD_DATE=$(shell date +%s)

generate:
	goproto-gen -p $(PACKAGE)/api
	cd $(PROTODIR)/src && \
	protoc -I=$(PROTODIR)/src -I=$(DIR)/vendor --gogo_out=:. --vine_out=:. $(PACKAGE)/api/rpc.proto

build:
	mkdir -p _output
	go build -a -installsuffix cgo -tags json1 -ldflags "-s -w ${LDFLAGS}" -o _output/rbac cmd/main.go

release: build

lint:
	golint .

clean:
	rm -fr vendor

.PHONY: generate build release clean