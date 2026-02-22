# Roadmap

## Phase 1 (current)

- Repository skeleton.
- Protocol parser/builder skeleton.
- Replay window.
- Crypto backend abstraction.
- Unit tests and CI baseline.

## Phase 2

- Production crypto backend integration (Magma CMAC/CTR through vetted library).
- ICV verification path and decrypt path in parser pipeline.
- Official Appendix A vectors (A.1-A.4) as golden tests.

## Phase 3

- `crispctl` control-plane commands.
- Datapath prototype in `crisp-driver`.
- Integration and interop tests.

## Phase 4

- Performance tuning and profiling.
- Hardening, fuzzing, and packaging/release automation.
