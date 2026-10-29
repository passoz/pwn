.PHONY: build test check lint fmt vet

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/pwn ./cmd/pwn

test:
	go test ./...

check: fmt vet lint test

fmt:
	test -z "$$(gofmt -l .)"

vet:
	go vet ./...

lint:
	golangci-lint run
