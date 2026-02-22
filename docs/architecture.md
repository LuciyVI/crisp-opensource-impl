# Architecture

## Components

- `crisp-core`: protocol implementation library.
- `crisp-driver`: future packet I/O datapath integration.
- `crispctl`: future control/diagnostics CLI.

## Planes

Data-plane responsibilities:

- Parse/build CRISP packets.
- Sequence number and anti-replay enforcement.
- Suite metadata and packet-level crypto invocation through backend interface.

Control-plane responsibilities:

- Key/session lifecycle management.
- Policy configuration and diagnostics.
- Integration with orchestration/system tooling.

## Dependency direction

- `crisp-driver` and `crispctl` depend on `crisp-core`.
- `crisp-core` depends on abstract crypto interface, not on concrete crypto libraries.
- Crypto backend implementations are pluggable and selected by integration layer.
