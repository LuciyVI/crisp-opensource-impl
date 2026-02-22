#ifndef CRISP_CORE_KEY_RESOLVER_H_
#define CRISP_CORE_KEY_RESOLVER_H_

#include <stdbool.h>
#include <stdint.h>

#include "crisp/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Metadata passed to key resolver for incoming packet key lookup. */
typedef struct crisp_key_resolve_request {
  bool external_key_id_flag;
  uint8_t cs;
  bool key_id_present;
  crisp_const_byte_span_t key_id;
  uint64_t seqnum;
} crisp_key_resolve_request_t;

/**
 * Resolves session keys for packet metadata.
 * Returned key spans must stay valid until caller finishes unprotect call.
 */
typedef crisp_error_t (*crisp_resolve_keys_fn)(void* user_ctx,
                                               const crisp_key_resolve_request_t* request,
                                               crisp_const_byte_span_t* out_kenc,
                                               crisp_const_byte_span_t* out_kmac);

/** Key resolver configuration for unprotect wrapper. */
typedef struct crisp_key_resolver {
  void* user_ctx;
  crisp_resolve_keys_fn resolve_keys;
  /** Whether packets with unused KeyId marker (0x80) are allowed. */
  bool allow_key_id_unused;
} crisp_key_resolver_t;

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // CRISP_CORE_KEY_RESOLVER_H_
