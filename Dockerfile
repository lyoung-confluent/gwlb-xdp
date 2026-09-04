# ---- dev: full BPF/netns toolchain the Makefile drives for `generate` and `verify`
FROM cgr.dev/chainguard/go:latest-dev AS dev
RUN apk add --no-cache clang llvm libbpf-dev bpftool mount
WORKDIR /work
ENTRYPOINT []

# ---- build: compile the static loader from the checked-in bindings.
FROM cgr.dev/chainguard/go AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/gwlb-xdp .

# ---- final: the static CGO-free binary on scratch.
FROM scratch AS final
COPY --from=build /out/gwlb-xdp /usr/local/bin/gwlb-xdp
ENTRYPOINT ["/usr/local/bin/gwlb-xdp"]
