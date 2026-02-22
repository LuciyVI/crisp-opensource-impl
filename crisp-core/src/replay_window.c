#include "crisp/core/replay_window.h"

#include <limits.h>
#include <string.h>

static bool crisp_get_bit(const crisp_replay_window_t* window, size_t index) {
  const size_t byte_index = index / 8U;
  const uint8_t mask = (uint8_t)(1U << (index % 8U));
  return (window->bits[byte_index] & mask) != 0U;
}

static void crisp_set_bit(crisp_replay_window_t* window, size_t index) {
  const size_t byte_index = index / 8U;
  const uint8_t mask = (uint8_t)(1U << (index % 8U));
  window->bits[byte_index] = (uint8_t)(window->bits[byte_index] | mask);
}

static void crisp_clear_bit(crisp_replay_window_t* window, size_t index) {
  const size_t byte_index = index / 8U;
  const uint8_t mask = (uint8_t)(1U << (index % 8U));
  window->bits[byte_index] = (uint8_t)(window->bits[byte_index] & (uint8_t)(~mask));
}

static void crisp_shift_window(crisp_replay_window_t* window, size_t delta) {
  if (delta >= window->size) {
    (void)memset(window->bits, 0, sizeof(window->bits));
    return;
  }

  for (size_t i = window->size; i > 0U; --i) {
    const size_t index = i - 1U;
    const bool value = (index >= delta) ? crisp_get_bit(window, index - delta) : false;
    if (value) {
      crisp_set_bit(window, index);
    } else {
      crisp_clear_bit(window, index);
    }
  }
}

crisp_error_t crisp_replay_window_init(crisp_replay_window_t* window, size_t size) {
  if (window == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (size < 1U || size > CRISP_REPLAY_WINDOW_MAX_SIZE) {
    return CRISP_ERR_OUT_OF_RANGE;
  }

  (void)memset(window, 0, sizeof(*window));
  window->size = size;
  return CRISP_OK;
}

crisp_error_t crisp_replay_window_check_and_update(crisp_replay_window_t* window,
                                                   uint64_t seqnum,
                                                   bool* accepted) {
  if (window == NULL || accepted == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (window->size < 1U || window->size > CRISP_REPLAY_WINDOW_MAX_SIZE) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (seqnum > CRISP_SEQNUM_MAX) {
    return CRISP_ERR_OUT_OF_RANGE;
  }

  if (!window->initialized) {
    (void)memset(window->bits, 0, sizeof(window->bits));
    window->max_seq = seqnum;
    window->initialized = true;
    crisp_set_bit(window, 0U);
    *accepted = true;
    return CRISP_OK;
  }

  if (seqnum > window->max_seq) {
    const uint64_t delta64 = seqnum - window->max_seq;
    if (delta64 >= (uint64_t)window->size) {
      (void)memset(window->bits, 0, sizeof(window->bits));
    } else {
      const size_t delta = (size_t)delta64;
      crisp_shift_window(window, delta);
    }
    window->max_seq = seqnum;
    crisp_set_bit(window, 0U);
    *accepted = true;
    return CRISP_OK;
  }

  const uint64_t distance64 = window->max_seq - seqnum;
  if (distance64 >= (uint64_t)window->size) {
    *accepted = false;
    return CRISP_OK;
  }
  if (distance64 > (uint64_t)SIZE_MAX) {
    *accepted = false;
    return CRISP_OK;
  }

  const size_t distance = (size_t)distance64;
  if (crisp_get_bit(window, distance)) {
    *accepted = false;
    return CRISP_OK;
  }

  crisp_set_bit(window, distance);
  *accepted = true;
  return CRISP_OK;
}
