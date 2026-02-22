#ifndef CRISP_CORE_MESSAGE_H_
#define CRISP_CORE_MESSAGE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crisp/core/key_resolver.h"
#include "crisp/core/replay_window.h"
#include "crisp/core/suites.h"
#include "crisp/core/types.h"
#include "crisp/crypto/iface.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Size of fixed pre-KeyId message prefix: ExternalKeyIdFlag|Version(15) + CS. */
#define CRISP_MESSAGE_HEADER_PREFIX_SIZE ((size_t)3U)
/** Size of SeqNum field in bytes. */
#define CRISP_MESSAGE_SEQNUM_SIZE ((size_t)6U)
/** Backward-compatible alias for fixed fields excluding variable KeyId/Payload/ICV. */
#define CRISP_MESSAGE_FIXED_HEADER_SIZE \
  (CRISP_MESSAGE_HEADER_PREFIX_SIZE + CRISP_MESSAGE_SEQNUM_SIZE)
/** Encoded marker meaning "KeyId not used". */
#define CRISP_KEY_ID_UNUSED_MARKER ((uint8_t)0x80U)
/** CRISP version mandated by GOST R 71252-2024. */
#define CRISP_VERSION_2024 ((uint16_t)0U)

/** Parsed CRISP message view referencing original packet memory. */
typedef struct crisp_message_view {
  bool external_key_id_flag;
  uint16_t version;
  uint8_t cs;
  bool key_id_present;
  crisp_const_byte_span_t key_id;
  uint64_t seqnum;
  crisp_const_byte_span_t payload;
  crisp_const_byte_span_t icv;
} crisp_message_view_t;

/** Input parameters for CRISP message serialization. */
typedef struct crisp_build_params {
  bool external_key_id_flag;
  uint16_t version;
  uint8_t cs;
  bool key_id_present;
  uint64_t seqnum;
  crisp_const_byte_span_t key_id;
  crisp_const_byte_span_t payload;
  crisp_const_byte_span_t kenc;
  crisp_const_byte_span_t kmac;
  const crisp_crypto_iface_t* crypto;
} crisp_build_params_t;

/** Input parameters for CRISP protect operation (plaintext -> wire packet). */
typedef struct crisp_protect_params {
  bool external_key_id_flag;
  uint8_t cs;
  bool key_id_present;
  uint64_t seqnum;
  crisp_const_byte_span_t key_id;
  crisp_const_byte_span_t payload;
  crisp_const_byte_span_t kenc;
  crisp_const_byte_span_t kmac;
  const crisp_crypto_iface_t* crypto;
} crisp_protect_params_t;

/** Input parameters for CRISP unprotect operation (wire packet -> plaintext). */
typedef struct crisp_unprotect_params {
  crisp_const_byte_span_t packet;
  crisp_const_byte_span_t kenc;
  crisp_const_byte_span_t kmac;
  const crisp_crypto_iface_t* crypto;
  crisp_replay_window_t* replay_window;
} crisp_unprotect_params_t;

/** Metadata returned by CRISP unprotect operation. */
typedef struct crisp_unprotect_result {
  bool external_key_id_flag;
  uint16_t version;
  uint8_t cs;
  bool key_id_present;
  crisp_const_byte_span_t key_id;
  uint64_t seqnum;
  crisp_mutable_byte_span_t plaintext;
} crisp_unprotect_result_t;

/**
 * Validates encoded KeyId bytes for use in CRISP packets.
 * Rules:
 * - 1-byte form when MSB(first byte) == 0;
 * - variable-length form when MSB == 1 and total_len = 1 + low7bits (2..128);
 * - 0x80 is reserved for "KeyId not used" and is not valid for this function.
 */
crisp_error_t crisp_validate_key_id(crisp_const_byte_span_t key_id);

/**
 * Parses a CRISP packet into lightweight field views.
 * Enforces max packet length (<=2048), Version==0, KeyId encoding rules,
 * SeqNum big-endian 48-bit encoding, and suite-specific ICV length.
 */
crisp_error_t crisp_parse_message(crisp_const_byte_span_t packet, crisp_message_view_t* out_message);

/**
 * Builds a CRISP packet into caller-provided buffer.
 * Uses crypto backend interface for CTR transform (suite-dependent, IV32=LSB32(SeqNum))
 * and CMAC ICV generation over the packet prefix (everything except ICV).
 */
crisp_error_t crisp_build_message(const crisp_build_params_t* params,
                                 crisp_mutable_byte_span_t out_packet,
                                 size_t* out_size);

/**
 * Protects plaintext into CRISP wire packet.
 * Equivalent to build with fixed Version=0 (GOST R 71252-2024).
 */
crisp_error_t crisp_protect(const crisp_protect_params_t* params,
                            crisp_mutable_byte_span_t out_packet,
                            size_t* out_size);

/**
 * Verifies/authenticates and decrypts CRISP wire packet.
 * Validates ICV in constant time and applies replay check (if replay_window provided).
 * Error mapping:
 * - parse/format/size issues: CRISP_ERR_INVALID_*
 * - ICV mismatch: CRISP_ERR_CRYPTO
 * - replay reject: CRISP_ERR_REPLAY
 * - out_plaintext too small: CRISP_ERR_BUFFER_TOO_SMALL
 * Contract:
 * - on CRISP_ERR_CRYPTO/CRISP_ERR_REPLAY/CRISP_ERR_BUFFER_TOO_SMALL and parse errors,
 *   output plaintext buffer is not modified.
 */
crisp_error_t crisp_unprotect(const crisp_unprotect_params_t* params,
                              crisp_mutable_byte_span_t out_plaintext,
                              crisp_unprotect_result_t* out_result);

/**
 * Resolves keys by packet metadata and then performs crisp_unprotect().
 * Wrapper parses packet first, calls resolver synchronously, and forwards resolved keys.
 * Policy:
 * - if KeyId is unused (0x80) and resolver.allow_key_id_unused == false -> CRISP_ERR_INVALID_FORMAT
 * - if resolver cannot find keys, resolver should return CRISP_ERR_INVALID_FORMAT
 */
crisp_error_t crisp_unprotect_resolve(crisp_const_byte_span_t packet,
                                      const crisp_key_resolver_t* resolver,
                                      const crisp_crypto_iface_t* crypto,
                                      crisp_replay_window_t* replay_window,
                                      crisp_mutable_byte_span_t out_plaintext,
                                      crisp_unprotect_result_t* out_result);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // CRISP_CORE_MESSAGE_H_
