GOFLAGS_BUILD := -trimpath -ldflags="-s -w"

.PHONY: build release test clean

# Host architecture
build:
	CGO_ENABLED=0 go build $(GOFLAGS_BUILD) -o vault ./cmd/vault
	CGO_ENABLED=0 go build $(GOFLAGS_BUILD) -o vaultd ./cmd/auth-daemon

# dist/linux-amd64/{vault,vaultd} and dist/linux-arm64/{vault,vaultd}
release:
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build $(GOFLAGS_BUILD) -o dist/linux-$$arch/vault ./cmd/vault || exit 1; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build $(GOFLAGS_BUILD) -o dist/linux-$$arch/vaultd ./cmd/auth-daemon || exit 1; \
	done

test:
	go vet ./...
	go test -count=1 -v ./tests/...

clean:
	rm -f vault vaultd
	rm -rf dist tests/testdata
