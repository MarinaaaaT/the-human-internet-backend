Real App Attest objects produced by Apple's service for a third-party sample
app (team `V8H6LQ9448`, bundle `io.uebelacker.AppAttestExample`), taken from
the MIT-licensed [`node-app-attest`](https://github.com/uebelack/node-app-attest)
test fixtures (Copyright (c) 2024 David Übelacker). They exercise the real
Apple certificate chain, which no locally generated object can. Their leaf
certificates have long since expired, so the tests verify them at a pinned
date rather than now.
