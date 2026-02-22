#include "crisp/crypto/dummy_backend.h"

#include <stddef.h>
#include <string.h>

static uint64_t crisp_dummy_seed(const void* user_ctx) {
  const crisp_dummy_crypto_state_t* state = (const crisp_dummy_crypto_state_t*)user_ctx;
  if (state == NULL || state->seed == 0U) {
    return 0xC0DEC0DE12345678ULL;
  }
  return state->seed;
}

static uint64_t crisp_mix64(uint64_t state, uint8_t value) {
  state ^= (uint64_t)value;
  state *= 0x100000001B3ULL;
  state ^= (state >> 29U);
  return state;
}

static crisp_error_t crisp_dummy_magma_cmac(void* user_ctx,
                                            crisp_const_byte_span_t key,
                                            crisp_const_byte_span_t data,
                                            crisp_mutable_byte_span_t out_icv) {
  if ((key.size > 0U && key.data == NULL) || (data.size > 0U && data.data == NULL) ||
      (out_icv.size > 0U && out_icv.data == NULL)) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  uint64_t state = crisp_dummy_seed(user_ctx) ^ 0x9E3779B97F4A7C15ULL;
  for (size_t i = 0U; i < key.size; ++i) {
    state = crisp_mix64(state, key.data[i]);
  }
  for (size_t i = 0U; i < data.size; ++i) {
    state = crisp_mix64(state, data.data[i]);
  }

  for (size_t i = 0U; i < out_icv.size; ++i) {
    state = crisp_mix64(state, (uint8_t)i);
    out_icv.data[i] = (uint8_t)(state >> ((i % 8U) * 8U));
  }

  return CRISP_OK;
}

static crisp_error_t crisp_dummy_magma_ctr_xcrypt(void* user_ctx,
                                                  crisp_const_byte_span_t key,
                                                  uint32_t iv32,
                                                  crisp_const_byte_span_t in,
                                                  crisp_mutable_byte_span_t out) {
  (void)user_ctx;
  if ((key.size > 0U && key.data == NULL) || (in.size > 0U && in.data == NULL) ||
      (out.size > 0U && out.data == NULL)) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (in.size != out.size) {
    return CRISP_ERR_INVALID_SIZE;
  }
  if (key.size == 0U) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  const size_t offset = (size_t)(iv32 & 0xFFU);
  for (size_t i = 0U; i < in.size; ++i) {
    const uint8_t iv_byte = (uint8_t)((iv32 >> ((i % 4U) * 8U)) & 0xFFU);
    const uint8_t key_byte = key.data[(i + offset) % key.size];
    const uint8_t stream = (uint8_t)(key_byte ^ iv_byte ^ (uint8_t)(0xA5U + (uint8_t)i));
    out.data[i] = (uint8_t)(in.data[i] ^ stream);
  }

  return CRISP_OK;
}

static crisp_error_t crisp_dummy_derive_kenc_kmac(void* user_ctx,
                                                  crisp_const_byte_span_t master_key,
                                                  crisp_const_byte_span_t salt,
                                                  crisp_mutable_byte_span_t out_kenc,
                                                  crisp_mutable_byte_span_t out_kmac) {
  if ((master_key.size > 0U && master_key.data == NULL) || (salt.size > 0U && salt.data == NULL) ||
      (out_kenc.size > 0U && out_kenc.data == NULL) ||
      (out_kmac.size > 0U && out_kmac.data == NULL)) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  uint64_t state = crisp_dummy_seed(user_ctx) ^ 0xA24BAED4963EE407ULL;
  for (size_t i = 0U; i < master_key.size; ++i) {
    state = crisp_mix64(state, master_key.data[i]);
  }
  for (size_t i = 0U; i < salt.size; ++i) {
    state = crisp_mix64(state, salt.data[i]);
  }

  for (size_t i = 0U; i < out_kenc.size; ++i) {
    state = crisp_mix64(state, (uint8_t)(i ^ 0x3CU));
    out_kenc.data[i] = (uint8_t)(state >> (8U * (i % 8U)));
  }

  for (size_t i = 0U; i < out_kmac.size; ++i) {
    state = crisp_mix64(state, (uint8_t)(i ^ 0xC3U));
    out_kmac.data[i] = (uint8_t)(state >> (8U * (i % 8U)));
  }

  return CRISP_OK;
}

void crisp_dummy_crypto_iface_init(crisp_crypto_iface_t* iface, crisp_dummy_crypto_state_t* state) {
  if (iface == NULL) {
    return;
  }

  (void)memset(iface, 0, sizeof(*iface));
  iface->user_ctx = state;
  iface->magma_cmac = crisp_dummy_magma_cmac;
  iface->magma_ctr_xcrypt = crisp_dummy_magma_ctr_xcrypt;
  iface->derive_kenc_kmac = crisp_dummy_derive_kenc_kmac;
}
