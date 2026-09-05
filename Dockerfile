# ---- dev: full BPF/netns toolchain the Makefile drives for `generate` and `verify`
FROM cgr.dev/chainguard/go:latest-dev AS dev
RUN apk add --no-cache clang llvm libbpf-dev bpftool mount
WORKDIR /work
ENTRYPOINT []

# ---- build: compile the static loader from the checked-in bindings. Runs on
# the builder's native platform and cross-compiles via GOOS/GOARCH — Go's
# cross-compilation needs no emulation, unlike running the target arch itself.
FROM --platform=$BUILDPLATFORM cgr.dev/chainguard/go:latest-dev AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/gwlb-xdp .

# ---- final: the static CGO-free binary on scratch.
FROM scratch AS final
COPY --from=build /out/gwlb-xdp /gwlb-xdp
ENTRYPOINT ["/gwlb-xdp"]
