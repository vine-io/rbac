NAME=$(shell echo "rbac")
PROTODIR=$(shell go env GOPATH)
DIR=$(shell pwd)
PACKAGE=github.com/vine-io/rbac
GIT_COMMIT=$(shell git rev-parse --short HEAD)
GIT_TAG=$(shell git describe --abbrev=0 --tags --always --match "v*")
GIT_VERSION=github.com/vine-io/rbac/pkg/internal/doc
CGO_ENABLED=0
BUILD_DATE=$(shell date +%s)
LDFLAGS=-X $(GIT_VERSION).GitCommit=$(GIT_COMMIT) -X $(GIT_VERSION).GitTag=$(GIT_TAG) -X $(GIT_VERSION).BuildDate=$(BUILD_DATE)

generate:
	goproto-gen -p $(PACKAGE)/api
	cd $(PROTODIR)/src && \
	protoc -I=$(PROTODIR)/src -I=$(DIR)/vendor --gogo_out=:. --vine_out=:. $(PACKAGE)/api/rpc.proto

release:
ifeq "$(TAG)" ""
	@echo "missing tag"
	exit 1
endif
	git tag $(TAG)
	make build-tag
	git add .
	git commit -m "$(TAG)"
	git tag -d $(TAG)
	git tag $(TAG)

build-tag:
	sed -i "" "s/GitTag     = ".*"/GitTag     = \"$(GIT_TAG)\"/g" pkg/internal/doc.go
	sed -i "" "s/GitCommit  = ".*"/GitCommit  = \"$(GIT_COMMIT)\"/g" pkg/internal/doc.go
	sed -i "" "s/BuildDate  = ".*"/BuildDate  = \"$(BUILD_DATE)\"/g" pkg/internal/doc.go

install:
	go install github.com/vine-io/vine/cmd/vine
	go install github.com/vine-io/vine/cmd/protoc-gen-gogo
	go install github.com/vine-io/vine/cmd/protoc-gen-vine
	go install github.com/vine-io/vine/cmd/protoc-gen-deepcopy
	go install github.com/vine-io/vine/cmd/protoc-gen-validator
	go install github.com/vine-io/vine/cmd/protoc-gen-dao

vendor:
	go mod vendor

build-darwin-amd64:

build-darwin-arm64:

build-windows:

build-linux-amd64:
	mkdir -p _output/linux
	GOOS=linux GOARCH=amd64 go build -o _output/linux/gpm -a -installsuffix cgo -ldflags "-s -w ${LDFLAGS}" cmd/gpm/main.go

build-linux-arm64:

build-amd: build-darwin-amd64 build-linux-amd64 build-windows

build-arm: build-darwin-arm64 build-linux-arm64 build-windows

build: build-amd build-arm

changelog:
	mkdir -p _output
	changelog --last --output _output/CHANGELOG.md

tar-amd: build-amd
	cd _output && \
	tar -zcvf rbac-darwin-amd64-$(GIT_TAG).tar.gz darwin/* && \
	tar -zcvf rbac-linux-amd64-$(GIT_TAG).tar.gz linux/*  && \
	zip rbac-windows-$(GIT_TAG).zip windows/* && \
	rm -fr darwin/ linux/ windows/

tar-arm: build-arm
	cd _output && \
	tar -zcvf rbac-darwin-arm64-$(GIT_TAG).tar.gz darwin/* && \
	tar -zcvf rbac-linux-arm64-$(GIT_TAG).tar.gz linux/*  && \
	rm -fr darwin/ linux/

tar: changelog tar-amd tar-arm

test-coverage:
	go test ./... -bench=. -coverage

lint:
	golint .

clean:
	rm -fr vendor

.PHONY: generate release build-tag vendor install build-darwin build-windows build-linux build tar clean