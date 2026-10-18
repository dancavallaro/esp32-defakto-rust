# esp-attest

The evidence an ESP32 sends when it attests to Defakto, and (behind the `verify` feature) the checks that verify
it. The firmware builds without `verify`, so it never compiles P-256. If you write another signer, such as
libcommon's C++ one, it must reproduce the golden vectors below byte for byte.

## Device IDs

1 to 64 characters of lowercase letters, digits, `.`, `_` and `-`, and neither `.` nor `..`. That keeps `|` out
of the signing string and makes every ID a safe file name. Evidence must stay 7-bit ASCII, because the trust domain
server mangles anything else on its way to the attestor; the device ID rules and lowercase hex guarantee that.

## HMAC evidence

The device signs `device_id|ts|nonce` with HMAC-SHA256, where `ts` is Unix seconds in decimal and `nonce` is 8
random bytes as 16 lowercase hex characters. It sends this JSON, with the fields in this order, no whitespace
and the MAC in lowercase hex:

    {"device_id":"…","ts":…,"nonce":"…","mac":"…"}

Golden vector: device `defakto-demo`, ts `1792200000`, nonce `0011223344556677`, and the secret bytes `0x00`
to `0x1f` (base64 `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=`) give the MAC
`b8eead1bcca6bc6368900c976dab032c0a7f8b8ac1427667e337904cf7a6c033`.

## ESP-TEE evidence

The TEE only signs a 32-bit nonce, so the device passes it the first 4 bytes, big-endian, of SHA-256 over the
same `device_id|ts|nonce`, with `client_id` `0x0DEFA470`. It wraps the TEE's token, unchanged, in an envelope:

    {"format":"esp-tee-eat/1","device_id":"…","ts":…,"nonce":"…","token":{…}}

The token's signature is ECDSA P-256 over SHA-256 of the exact bytes of its `header`, `eat` and `public_key`
objects, concatenated in that order; `sign.r` and `sign.s` are hex. The verifier checks, in this order, that
`header.sign_alg` is `ecdsa_secp256r1_sha256`, that `public_key.compressed` is the enrolled key, the signature,
and that the low 32 bits of `eat.nonce` and `eat.client_id` (which the TEE prints as signed decimals) match the
envelope's TEE nonce and `0x0DEFA470`.

Golden vector: `testdata/tee_envelope_golden.json`, captured from a TEE with device `defakto-demo`, ts
`1792200000` and nonce `0011223344556677`. Its TEE nonce is `0x78a5dd58`, and it verifies against the key
`02cded7398be59dd931161ccf6ecc7482894f7411e6b5c768f5941e838ce12cdba`. A signer can't reproduce the TEE's
signature, but it must produce that TEE nonce and the same envelope around the same token.

## Differences from the Go verifier

This crate replaced a Go verifier and accepts every genuine token it did. It keeps Go's leniency where a genuine
device could need it: `r` and `s` may drop leading zeros, `eat.nonce` and `eat.client_id` may be any 64-bit
integer whose low 32 bits match, and `eat.sw_claims` and anything in it may be absent, reading as empty, 0 or
false. On malformed input it differs deliberately, and apart from the first point it is stricter:

- It reads only exact keys and ignores any that differ in case, where Go would let `"Device_ID"` override
  `device_id`. That can't help a forger: the signature and nonce binding are checked against the fields it reads.
- Fields are required rather than read as zero values, apart from `sw_claims`.
- A repeated key is an error rather than the last one winning.
- Invalid UTF-8, in a field it reads or in the signed objects, is rejected rather than replaced.
- `r` and `s` must be bare hex digits; Go's `big.Int` also took a leading sign.
