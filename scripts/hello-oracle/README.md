# hello-oracle

The byte-identity oracle for the `cipher_suites` field of a Go `crypto/tls`
ClientHello. It drives the standard library over an in-memory pipe and prints
the field for each scripted config, so `crates/ferrox-core/src/tls/cipher_suites.rs`
can be compared byte for byte.

The oracle uses only the Go standard library, so no upstream checkout is needed.
From this directory:

```sh
go run . < script.txt > expected.txt
```

`script.txt` is hand-written: one case per line, grammar in `main.go`. The
command regenerates `expected.txt`; diff both files after any change.
