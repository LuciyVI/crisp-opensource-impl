#ifndef CRISP_CRYPTO_DUMMY_BACKEND_H_
#define CRISP_CRYPTO_DUMMY_BACKEND_H_

#include <stdint.h>

#include "crisp/crypto/iface.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Deterministic state for dummy crypto backend used in tests. */
typedef struct crisp_dummy_crypto_state {
  uint64_t seed;
} crisp_dummy_crypto_state_t;

/**
 * Initializes deterministic non-cryptographic backend.
 * WARNING: this backend is only for tests and must not be used in production.
 */
void crisp_dummy_crypto_iface_init(crisp_crypto_iface_t* iface, crisp_dummy_crypto_state_t* state);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // CRISP_CRYPTO_DUMMY_BACKEND_H_
