.PHONY: all test server certs clean

all: test server

test:
	cargo test --workspace

server:
	cargo build --release -p crisper-teamserver

certs:
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 \
		-keyout certs/server.key -out certs/server.pem \
		-days 365 -nodes -subj "/CN=crisper"

clean:
	cargo clean
