# AegisProxy build & test entry points. No target changes the working directory of the caller.
VERSION ?= 2.1.0
# Image names of the release workflow (ghcr.io/<owner>/aegisproxy-<component>:v<version>), the Helm chart's defaults.
REGISTRY ?= ghcr.io/atomfritte
IMAGE_TAG ?= v$(VERSION)
GO ?= go
PY ?= python3
HELM ?= helm
WINE_WORK ?= /tmp/aegis-wine
CONFORMANCE_WORK ?= /tmp/aegis-conformance
PWSH_IMAGE ?= mcr.microsoft.com/powershell:7.5-ubuntu-24.04

.PHONY: all build build-control-plane build-windows build-console test test-go test-go-cluster test-python test-frontend test-console-e2e lint-helm test-installers test-windows-wine test-conformance images clean

all: test build

build: build-control-plane build-console

build-control-plane:
	CGO_ENABLED=0 $(GO) -C control-plane build -trimpath -ldflags "-s -w -X main.Version=$(VERSION)" -o ../dist/aegis-control-plane .

build-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) -C control-plane build -trimpath -ldflags "-s -w -X main.Version=$(VERSION)" -o ../dist/aegis-control-plane.exe .

build-console:
	npm --prefix frontend ci --no-audit --no-fund
	npm --prefix frontend run build

test: test-go test-python test-frontend lint-helm

test-go:
	$(GO) -C control-plane vet ./...
	$(GO) -C control-plane test -race -count=1 -timeout 30m ./...

# Requires AEGIS_TEST_DATABASE_URL (see docs/testing.md)
test-go-cluster:
	$(GO) -C control-plane test -race -count=1 -run 'TestCluster' -v ./internal/store/

test-python:
	$(PY) -I data-plane/tests/test_dataplane.py

test-frontend:
	npm --prefix frontend run build

# Console regression suite (Playwright for Python from frontend/e2e/requirements.txt + Chromium; see docs/testing.md)
test-console-e2e: build-control-plane build-console
	PYTHON=$(PY) frontend/e2e/run.sh dist/aegis-control-plane frontend/dist

# Windows installers (Pester against an in-memory Windows model; needs Docker)
test-installers:
	docker run --rm -u $$(id -u):$$(id -g) -e HOME=/tmp -v $(CURDIR):/repo:ro -w /repo $(PWSH_IMAGE) \
		pwsh -NoProfile -File deploy/windows/tests/Invoke-InstallerTests.ps1 -OutputDir /tmp/pester-results

# Windows builds under Wine incl. PostgreSQL cluster tests (needs Docker; see scripts/wine/README.md)
test-windows-wine:
	scripts/wine/run-go-tests.sh $(WINE_WORK) --cluster

# Splunk HEC, Sentinel and public Microsoft/Datadog endpoints against reference implementations (needs Docker)
test-conformance:
	scripts/conformance/run.sh $(CONFORMANCE_WORK)

lint-helm:
	$(HELM) lint deploy/helm/aegisproxy --set storage.postgres.url=postgres://u:p@db/aegis --set 'networkPolicy.proxyClientCIDRs={10.0.0.0/8}'
	$(HELM) lint deploy/helm/aegisproxy --set storage.type=file --set console.enabled=true --set 'dataPlane.service.loadBalancerSourceRanges={10.0.0.0/8}'

images:
	docker build -t $(REGISTRY)/aegisproxy-control-plane:$(IMAGE_TAG) --build-arg VERSION=$(VERSION) .
	docker build -t $(REGISTRY)/aegisproxy-control-plane-api:$(IMAGE_TAG) --build-arg VERSION=$(VERSION) control-plane
	docker build -t $(REGISTRY)/aegisproxy-data-plane:$(IMAGE_TAG) data-plane
	docker build -t $(REGISTRY)/aegisproxy-console:$(IMAGE_TAG) frontend

clean:
	rm -rf dist frontend/dist
