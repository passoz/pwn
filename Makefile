.PHONY: build test test-race check lint fmt vet

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/pwn ./cmd/pwn

test:
	go test ./...

test-race:
	CGO_ENABLED=1 go test -race ./...

check: fmt vet lint test build
	./bin/pwn self-check
	./bin/pwn validate

fmt:
	test -z "$$(gofmt -l .)"

vet:
	go vet ./...

lint:
	golangci-lint run
