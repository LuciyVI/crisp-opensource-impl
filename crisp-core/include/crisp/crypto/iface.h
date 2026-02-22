#ifndef CRISP_CRYPTO_IFACE_H_
#define CRISP_CRYPTO_IFACE_H_

#include <stdint.h>

#include "crisp/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Backend callback for Magma-CMAC calculation. */
typedef crisp_error_t (*crisp_magma_cmac_fn)(void* user_ctx,
                                             crisp_const_byte_span_t key,
                                             crisp_const_byte_span_t data,
                                             crisp_mutable_byte_span_t out_icv);

/** Backend callback for Magma-CTR encrypt/decrypt operation. */
typedef crisp_error_t (*crisp_magma_ctr_xcrypt_fn)(void* user_ctx,
                                                   crisp_const_byte_span_t key,
                                                   uint32_t iv32,
                                                   crisp_const_byte_span_t in,
                                                   crisp_mutable_byte_span_t out);

/** Backend callback for deriving Kenc/Kmac from master material. */
typedef crisp_error_t (*crisp_derive_kenc_kmac_fn)(void* user_ctx,
                                                   crisp_const_byte_span_t master_key,
                                                   crisp_const_byte_span_t salt,
                                                   crisp_mutable_byte_span_t out_kenc,
                                                   crisp_mutable_byte_span_t out_kmac);

/**
 * Crypto backend vtable.
 * All cryptographic operations in CRISP core must be routed through this interface.
 */
typedef struct crisp_crypto_iface {
  void* user_ctx;
  crisp_magma_cmac_fn magma_cmac;
  crisp_magma_ctr_xcrypt_fn magma_ctr_xcrypt;
  crisp_derive_kenc_kmac_fn derive_kenc_kmac;
} crisp_crypto_iface_t;

/**
 * Calls backend Kenc/Kmac derivation routine.
 * Returns CRISP_ERR_INVALID_ARGUMENT if the backend or callback is missing.
 */
crisp_error_t crisp_derive_kenc_kmac(const crisp_crypto_iface_t* iface,
                                     crisp_const_byte_span_t master_key,
                                     crisp_const_byte_span_t salt,
                                     crisp_mutable_byte_span_t out_kenc,
                                     crisp_mutable_byte_span_t out_kmac);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // CRISP_CRYPTO_IFACE_H_
