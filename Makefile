.PHONY: test vet fmt check

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

check: test vet
