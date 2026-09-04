IMAGE    := gwlb-xdp-dev
PLATFORM ?= linux/$(shell uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')

.PHONY: all generate loader verify clean docker-build docker-shell docker-image

all: loader

generate: docker-build
	docker run --rm --platform=$(PLATFORM) -v $(CURDIR):/work $(IMAGE) go generate ./...

loader: docker-build
	docker run --rm --platform=$(PLATFORM) -v $(CURDIR):/work $(IMAGE) go build -o gwlb-xdp .

verify: docker-build
	docker run --rm --privileged --platform=$(PLATFORM) -v $(CURDIR):/work $(IMAGE) sh -euc '\
		go generate ./...; \
		mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true; \
		arch=$$(uname -m | sed "s/x86_64/x86/; s/aarch64/arm64/"); \
		for p in decap encap; do \
			obj="bpf/$$p/bpf_$${arch}_bpfel.o"; \
			pin="/sys/fs/bpf/gwlb_verify_$$p"; \
			bpftool prog load "$$obj" "$$pin"; \
			bpftool prog show pinned "$$pin"; \
			rm "$$pin"; \
		done'

docker-build:
	docker build --platform=$(PLATFORM) --target dev -t $(IMAGE) .

clean:
	rm -f gwlb-xdp

docker-shell: docker-build
	docker run --rm -it --privileged --platform=$(PLATFORM) -v $(CURDIR):/work $(IMAGE) bash

docker-image:
	docker build --platform=$(PLATFORM) --target final -t gwlb-xdp .
