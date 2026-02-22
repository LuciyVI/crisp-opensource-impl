# CRISP test vectors (placeholder)

This folder is reserved for vectors from Appendix A of GOST R 71252-2024:

- A.1
- A.2
- A.3
- A.4

Planned storage format:

- One full wire packet per file in lowercase hex without separators.
- Suggested file naming: `A1_case01_packet.hex`, `A1_case01_expected_icv.hex`, `A1_case01_meta.txt`.
- `*_packet.hex` must follow GOST wire layout:
  `ExternalKeyIdFlag|Version(15)` (BE16), `CS` (8-bit), `KeyId` (varlen), `SeqNum` (BE48), `Payload`, `ICV`.
- `*_meta.txt` should contain CS, KeyId encoding form, SeqNum, payload length, and expected parse fields.

TODO:

- Add raw vectors.
- Add parser/serializer golden tests consuming these files.
