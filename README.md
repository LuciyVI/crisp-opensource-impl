<<<<<<< HEAD
# crisp-opensource-impl
=======
# CRISP

Reference open source skeleton for CRISP protocol implementation in C/C++
(GOST R 71252-2024).

## Project goal

Create a production-grade, testable, cross-platform user-space CRISP library (Linux first),
with clear separation of protocol core, crypto backend abstraction, and integration layers.

## Current status

Implemented in this skeleton:

- `crisp-core` static library with:
- CRISP message parser/builder (`<= 2048` bytes, big-endian SeqNum(48-bit), KeyId checks).
- Suite metadata (`CS1..CS4`, ICV length, encryption flag).
- Anti-replay sliding window (`1..256`) with bitset + `max_seq`.
- Crypto backend interface (`magma_cmac`, `magma_ctr_xcrypt`, key derivation hook).
- Deterministic dummy crypto backend for unit tests.
- `crispctl` CLI stub.
- `crisp-driver` placeholder docs.
- Catch2-based unit tests and placeholders for golden vectors from GOST Appendix A.
- CI workflow for Linux (gcc/clang, Debug/Release, tests).

## Repository layout

- `crisp-core/` protocol core library and public headers.
- `crisp-driver/` datapath/driver placeholder.
- `crispctl/` CLI placeholder.
- `tests/` unit tests + vector placeholders + integration test stubs.
- `cmake/` warnings/sanitizers/clang-tidy helper modules.
- `docs/` architecture, protocol notes, build guide, roadmap.

## Build (quick start)

```bash
cmake -S . -B build -DCRISP_BUILD_TESTS=ON -DCRISP_BUILD_TOOLS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

## Roadmap

- Real crypto backend integration (no custom crypto implementation).
- Transport bindings and datapath integration.
- Control-plane commands in `crispctl`.
- Interop suite with official Appendix A vectors.
- VPN/system integration adapters.

## Security note

`crisp-core/src/dummy_crypto_backend.c` is test-only and not cryptographically secure.
>>>>>>> 0553303 (Initial commit)
