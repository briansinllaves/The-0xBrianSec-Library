
Detection

- `"AC ED 00 05"` in Hex
    - `AC ED`: STREAM_MAGIC. Specifies that this is a serialization protocol.
    - `00 05`: STREAM_VERSION. The serialization version.
- `"rO0"` in Base64
- Content-type = "application/x-java-serialized-object"
- `"H4sIAAAAAAAAAJ"` in gzip(base64)


