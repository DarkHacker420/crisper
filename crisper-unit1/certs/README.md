# certs

Generate a self-signed pair for the listener:

    openssl req -x509 -newkey rsa:4096 \
        -keyout certs/server.key -out certs/server.pem \
        -days 365 -nodes -subj "/CN=crisper"

`teamserver.yaml` points at `certs/server.pem` and `certs/server.key`.

The implant pins the SPKI SHA-256 of the leaf certificate. To print it:

    openssl x509 -in certs/server.pem -pubkey -noout \
        | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary | openssl base64

Paste that value into the implant build config as `SPKI_PIN`.
Regenerate the pair and the pin together; a mismatch is a hard failure
at TLS handshake, not a warning.
