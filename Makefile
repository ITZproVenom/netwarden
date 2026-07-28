.PHONY: test vet fmt check gui-dev gui-build

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

check: test vet

gui-dev:
	cd cmd/netwarden-gui && wails dev

gui-build:
	cd cmd/netwarden-gui && wails build
