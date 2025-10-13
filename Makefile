BIN := bin/cookie-guard-spoa

.PHONY: all build clean

all: build

build:
	@mkdir -p bin
	GOFLAGS='-trimpath' \
	LD_FLAGS='-s -w' \
	go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/cookie-guard-spoa

clean:
	rm -rf bin dist
