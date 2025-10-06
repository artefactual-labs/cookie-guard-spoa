BIN := bin/js-spoa

.PHONY: all build clean

all: build

build:
	@mkdir -p bin
	GOFLAGS='-trimpath' \
	LD_FLAGS='-s -w' \
	go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/js-spoa

clean:
	rm -rf bin dist

