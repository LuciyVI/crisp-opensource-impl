#ifndef CRISP_CORE_REPLAY_WINDOW_H_
#define CRISP_CORE_REPLAY_WINDOW_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crisp/core/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum anti-replay window size (in sequence numbers). */
#define CRISP_REPLAY_WINDOW_MAX_SIZE ((size_t)256U)

/** Sliding anti-replay window with fixed storage for up to 256 entries. */
typedef struct crisp_replay_window {
  size_t size;
  uint64_t max_seq;
  bool initialized;
  uint8_t bits[CRISP_REPLAY_WINDOW_MAX_SIZE / 8U];
} crisp_replay_window_t;

/**
 * Initializes replay window with a configured size in range [1..256].
 */
crisp_error_t crisp_replay_window_init(crisp_replay_window_t* window, size_t size);

/**
 * Checks SeqNum against replay window and updates state.
 * Returns CRISP_OK and sets `accepted=false` if packet is too old or replayed.
 * Not thread-safe: caller must provide synchronization for concurrent access.
 */
crisp_error_t crisp_replay_window_check_and_update(crisp_replay_window_t* window,
                                                   uint64_t seqnum,
                                                   bool* accepted);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // CRISP_CORE_REPLAY_WINDOW_H_
