# CRISP message model (GOST R 71252-2024)

CRISP packet layout on wire:

1. Octets 0..1 (`uint16`, big-endian): `ExternalKeyIdFlag(1 bit, MSB) | Version(15 bits)`
2. Octet 2: `CS` (`1..4`)
3. Next bytes: `KeyId` (variable length; see encoding rules below)
4. Next 6 bytes: `SeqNum` (48-bit, big-endian)
5. Next bytes: `PayloadData` (variable)
6. Last `ICVLen` bytes: `ICV`

## Version

- `Version` is fixed to `0` by the standard.
- Parser accepts only `Version == 0`.
- Builder emits only `Version == 0`.

## CS mapping

- `CS=1` (`MAGMA-CTR-CMAC`): encryption enabled, `ICVLen=4`
- `CS=2` (`MAGMA-NULL-CMAC`): encryption disabled, `ICVLen=4`
- `CS=3` (`MAGMA-CTR-CMAC8`): encryption enabled, `ICVLen=8`
- `CS=4` (`MAGMA-NULL-CMAC8`): encryption disabled, `ICVLen=8`

## KeyId encoding

- If MSB of first KeyId byte is `0`: KeyId length is exactly `1` byte.
- If MSB is `1`: total length is `1 + low7bits(first_byte)` (so `2..128` bytes).
- Special value `0x80` means `KeyId not used`; no extra KeyId bytes follow.

Parser enforces KeyId bounds and packet bounds, and the total packet size must be `<= 2048` bytes.

## SeqNum and IV32

- `SeqNum` is a 48-bit unsigned integer (`<= 0x0000FFFFFFFFFFFF`).
- For encryption suites, `IV32` is derived as `LSB32(SeqNum)` inside builder/protect logic.

## ICV handling

- `ICV` length is selected by CS (`4` or `8` bytes).
- While parsing, payload is separated as: `payload = packet[... len - ICVLen)`.
- While building, CMAC input is the entire packet except ICV itself.

## Core API unprotect contract

- `crisp_unprotect()` returns:
  - parse/format/size errors as `CRISP_ERR_INVALID_*`
  - ICV mismatch as `CRISP_ERR_CRYPTO`
  - anti-replay reject as `CRISP_ERR_REPLAY`
  - small output buffer as `CRISP_ERR_BUFFER_TOO_SMALL`
- `crisp_unprotect()` must not modify caller plaintext output buffer when it returns:
  - parse/format/size errors
  - `CRISP_ERR_CRYPTO`
  - `CRISP_ERR_REPLAY`
  - `CRISP_ERR_BUFFER_TOO_SMALL`

## Resolver wrapper contract

- `crisp_unprotect_resolve()` flow:
  1. parse packet metadata (`external_key_id_flag`, `cs`, `key_id`, `seqnum`)
  2. call key resolver callback
  3. call `crisp_unprotect()` with resolved keys
- key resolver receives `key_id` as span referencing packet memory.
  - lifetime is only for synchronous callback execution.
  - resolver must not cache pointer past callback return.
- default KeyId policy in wrapper:
  - if packet uses KeyId unused marker (`0x80`) and `allow_key_id_unused == false`,
    wrapper returns `CRISP_ERR_INVALID_FORMAT`.
- resolver "key not found" policy:
  - resolver should return `CRISP_ERR_INVALID_FORMAT`.

## Replay window threading

- `crisp_replay_window_t` operations are not thread-safe.
- caller (e.g. driver RX pipeline) must provide locking/synchronization around
  `crisp_replay_window_check_and_update()`.
