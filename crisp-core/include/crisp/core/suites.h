#ifndef CRISP_CORE_SUITES_H_
#define CRISP_CORE_SUITES_H_

#include <stdbool.h>
#include <stddef.h>

#include "crisp/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** CRISP cryptographic suites (CS=1..4). */
typedef enum crisp_suite {
  /** CS=1 MAGMA-CTR-CMAC (enc=true, icv=4). */
  CRISP_SUITE_CS1 = 1,
  /** CS=2 MAGMA-NULL-CMAC (enc=false, icv=4). */
  CRISP_SUITE_CS2 = 2,
  /** CS=3 MAGMA-CTR-CMAC8 (enc=true, icv=8). */
  CRISP_SUITE_CS3 = 3,
  /** CS=4 MAGMA-NULL-CMAC8 (enc=false, icv=8). */
  CRISP_SUITE_CS4 = 4,
} crisp_suite_t;

/** Derived parameters for selected suite. */
typedef struct crisp_suite_params {
  size_t icv_size;
  bool encryption_enabled;
} crisp_suite_params_t;

/**
 * Resolves suite parameters.
 * Returns CRISP_ERR_UNSUPPORTED_SUITE for unknown suite values.
 */
crisp_error_t crisp_suite_get_params(crisp_suite_t suite, crisp_suite_params_t* out_params);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // CRISP_CORE_SUITES_H_
