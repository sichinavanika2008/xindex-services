# Test fixtures — THROWAWAY keys

These RSA PEMs are **test-only, throwaway** keypairs generated for the
`jwt` / `server` round-trip unit tests. They are **not** secrets and are
**never** used outside `#[cfg(test)]`:

- `test_node_priv.pem` / `test_node_pub.pem` — stands in for a Cobo TSS-Node's
  RSA keypair (sign a request JWT with the priv, verify with the pub).
- `test_other_pub.pem` — an unrelated public key, used to prove a request
  signed by the node key is REJECTED under a different key.

If a secret scanner flags `test_node_priv.pem`, allowlist this path — it is a
disposable test vector with no production use. Regenerate any time with:

```
openssl genrsa -out test_node_priv.pem 2048
openssl rsa -in test_node_priv.pem -pubout -out test_node_pub.pem
```
