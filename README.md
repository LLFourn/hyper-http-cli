## Hyper HTTP connections

This simple CLI connects to HTTP/HTTPs servers and makes a GET request.
It has an option to use a HTTP CONNECT proxy (but not https yet).

This was done so I could figure out how you're meant to fit hyper and tokio etc together.


### Synopsis


```
cargo run -- https://blockstream.info/api/blocks/tip/height
cargo run -- --proxy 127.0.0.1:8100 https://blockstream.info/api/blocks/tip/height
```
