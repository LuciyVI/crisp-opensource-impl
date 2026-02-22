#ifndef CRISP_CORE_TYPES_H_
#define CRISP_CORE_TYPES_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum supported CRISP message size in bytes. */
#define CRISP_MAX_MESSAGE_SIZE ((size_t)2048U)
/** Maximum encoded KeyId length in bytes. */
#define CRISP_MAX_KEY_ID_SIZE ((size_t)128U)
/** CRISP SeqNum bit width. */
#define CRISP_SEQNUM_BITS (48U)
/** Max value for 48-bit SeqNum. */
#define CRISP_SEQNUM_MAX ((uint64_t)0x0000FFFFFFFFFFFFULL)

/** Error/status codes returned by CRISP APIs. */
typedef enum crisp_error {
  CRISP_OK = 0,
  CRISP_ERR_INVALID_ARGUMENT,
  CRISP_ERR_BUFFER_TOO_SMALL,
  CRISP_ERR_INVALID_SIZE,
  CRISP_ERR_INVALID_FORMAT,
  CRISP_ERR_UNSUPPORTED_SUITE,
  CRISP_ERR_REPLAY,
  CRISP_ERR_OUT_OF_RANGE,
  CRISP_ERR_CRYPTO,
} crisp_error_t;

/** Immutable byte range. */
typedef struct crisp_const_byte_span {
  const uint8_t* data;
  size_t size;
} crisp_const_byte_span_t;

/** Mutable byte range. */
typedef struct crisp_mutable_byte_span {
  uint8_t* data;
  size_t size;
} crisp_mutable_byte_span_t;

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // CRISP_CORE_TYPES_H_
