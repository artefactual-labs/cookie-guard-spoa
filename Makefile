BIN := bin/cookie-guard-spoa

.PHONY: all build clean altcha-assets install-altcha-assets altcha-go-bump botd-assets install-botd-assets

all: build

build:
	@mkdir -p bin
	GOFLAGS='-trimpath' \
	LD_FLAGS='-s -w' \
	go build -trimpath -ldflags="-s -w" -o $(BIN) ./cmd/cookie-guard-spoa

clean:
	rm -rf bin dist

# ----- ALTCHA / BotD assets management -----
ALTCHA_VER := $(shell sed -n '1p' web/assets/altcha/VERSION 2>/dev/null || echo unset)
BOTD_VER := $(shell sed -n '1p' web/assets/botd/VERSION 2>/dev/null || echo unset)

altcha-assets:
	@[ -x tools/altcha-sync.sh ] || chmod +x tools/altcha-sync.sh || true
	./tools/altcha-sync.sh $(ALTCHA_VER)

install-altcha-assets:
	install -d -m0755 /etc/haproxy/assets/altcha
	cp -a web/assets/altcha/* /etc/haproxy/assets/altcha/

botd-assets:
	@[ -x tools/botd-sync.sh ] || chmod +x tools/botd-sync.sh || true
	./tools/botd-sync.sh $(BOTD_VER)

install-botd-assets:
	install -d -m0755 /etc/haproxy/assets/botd
	cp -a web/assets/botd/* /etc/haproxy/assets/botd/

altcha-go-bump:
	@if [ -z "$(VERSION)" ]; then echo "usage: make altcha-go-bump VERSION=vX.Y.Z"; exit 2; fi
	go get github.com/altcha-org/altcha-lib-go@$(VERSION)
	go mod tidy
