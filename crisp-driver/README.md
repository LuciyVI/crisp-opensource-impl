# crisp-driver

`crisp-driver` is a placeholder for data-plane integration.

Planned implementation variants:

- Linux kernel module for L3/L4 data path interception and CRISP encapsulation.
- Linux userspace fast path (e.g. AF_XDP/DPDK style integration) with `crisp-core` as protocol engine.
- Portable userspace adapter for integration tests and reference deployments.

Current state: no packet I/O implementation yet; only project scaffolding.
