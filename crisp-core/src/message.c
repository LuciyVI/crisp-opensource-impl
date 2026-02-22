#include "crisp/core/message.h"

#include <limits.h>
#include <string.h>

enum {
  CRISP_INTERNAL_MAX_ICV_SIZE = 8,
};

static crisp_error_t crisp_checked_add_size(size_t lhs, size_t rhs, size_t* out) {
  if (out == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (SIZE_MAX - lhs < rhs) {
    return CRISP_ERR_OUT_OF_RANGE;
  }
  *out = lhs + rhs;
  return CRISP_OK;
}

static uint64_t crisp_read_be48(const uint8_t* bytes) {
  uint64_t value = 0U;
  for (size_t i = 0U; i < CRISP_MESSAGE_SEQNUM_SIZE; ++i) {
    value = (value << 8U) | (uint64_t)bytes[i];
  }
  return value;
}

static void crisp_write_be48(uint64_t value, uint8_t* out) {
  for (size_t i = 0U; i < CRISP_MESSAGE_SEQNUM_SIZE; ++i) {
    out[CRISP_MESSAGE_SEQNUM_SIZE - 1U - i] = (uint8_t)(value & 0xFFU);
    value >>= 8U;
  }
}

static bool crisp_constant_time_equal(const uint8_t* lhs, const uint8_t* rhs, size_t size) {
  uint8_t diff = 0U;
  for (size_t i = 0U; i < size; ++i) {
    diff = (uint8_t)(diff | (uint8_t)(lhs[i] ^ rhs[i]));
  }
  return diff == 0U;
}

static void crisp_secure_zero(void* data, size_t size) {
  if (data == NULL || size == 0U) {
    return;
  }
  volatile uint8_t* p = (volatile uint8_t*)data;
  for (size_t i = 0U; i < size; ++i) {
    p[i] = 0U;
  }
}

static crisp_error_t crisp_decode_key_id(crisp_const_byte_span_t packet,
                                         size_t offset,
                                         bool* out_key_id_present,
                                         crisp_const_byte_span_t* out_key_id,
                                         size_t* out_key_id_size) {
  if (out_key_id_present == NULL || out_key_id == NULL || out_key_id_size == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (offset >= packet.size) {
    return CRISP_ERR_INVALID_SIZE;
  }

  const uint8_t first = packet.data[offset];
  if (first == CRISP_KEY_ID_UNUSED_MARKER) {
    *out_key_id_present = false;
    out_key_id->data = NULL;
    out_key_id->size = 0U;
    *out_key_id_size = 1U;
    return CRISP_OK;
  }

  if ((first & 0x80U) == 0U) {
    *out_key_id_present = true;
    out_key_id->data = packet.data + offset;
    out_key_id->size = 1U;
    *out_key_id_size = 1U;
    return CRISP_OK;
  }

  const size_t total_len = 1U + (size_t)(first & 0x7FU);
  if (total_len < 2U || total_len > CRISP_MAX_KEY_ID_SIZE) {
    return CRISP_ERR_INVALID_FORMAT;
  }

  size_t end = 0U;
  crisp_error_t err = crisp_checked_add_size(offset, total_len, &end);
  if (err != CRISP_OK) {
    return err;
  }
  if (end > packet.size) {
    return CRISP_ERR_INVALID_SIZE;
  }

  *out_key_id_present = true;
  out_key_id->data = packet.data + offset;
  out_key_id->size = total_len;
  *out_key_id_size = total_len;
  return CRISP_OK;
}

crisp_error_t crisp_validate_key_id(crisp_const_byte_span_t key_id) {
  if (key_id.size > 0U && key_id.data == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (key_id.size < 1U || key_id.size > CRISP_MAX_KEY_ID_SIZE) {
    return CRISP_ERR_INVALID_SIZE;
  }

  const uint8_t first = key_id.data[0];
  if (first == CRISP_KEY_ID_UNUSED_MARKER) {
    return CRISP_ERR_INVALID_FORMAT;
  }

  if ((first & 0x80U) == 0U) {
    if (key_id.size != 1U) {
      return CRISP_ERR_INVALID_FORMAT;
    }
    return CRISP_OK;
  }

  const size_t total_len = 1U + (size_t)(first & 0x7FU);
  if (total_len != key_id.size) {
    return CRISP_ERR_INVALID_FORMAT;
  }

  return CRISP_OK;
}

crisp_error_t crisp_parse_message(crisp_const_byte_span_t packet, crisp_message_view_t* out_message) {
  if (out_message == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (packet.data == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (packet.size > CRISP_MAX_MESSAGE_SIZE) {
    return CRISP_ERR_INVALID_SIZE;
  }

  const size_t min_possible_size = CRISP_MESSAGE_HEADER_PREFIX_SIZE + 1U + CRISP_MESSAGE_SEQNUM_SIZE + 4U;
  if (packet.size < min_possible_size) {
    return CRISP_ERR_INVALID_SIZE;
  }

  (void)memset(out_message, 0, sizeof(*out_message));

  const uint16_t first16 = (uint16_t)(((uint16_t)packet.data[0] << 8U) | (uint16_t)packet.data[1]);
  const bool external_key_id_flag = (first16 & 0x8000U) != 0U;
  const uint16_t version = (uint16_t)(first16 & 0x7FFFU);
  if (version != CRISP_VERSION_2024) {
    return CRISP_ERR_INVALID_FORMAT;
  }

  const uint8_t cs = packet.data[2];
  crisp_suite_params_t suite_params;
  crisp_error_t err = crisp_suite_get_params((crisp_suite_t)cs, &suite_params);
  if (err != CRISP_OK) {
    return err;
  }

  const size_t key_id_offset = CRISP_MESSAGE_HEADER_PREFIX_SIZE;
  bool key_id_present = false;
  crisp_const_byte_span_t key_id = {0};
  size_t key_id_size = 0U;
  err = crisp_decode_key_id(packet, key_id_offset, &key_id_present, &key_id, &key_id_size);
  if (err != CRISP_OK) {
    return err;
  }

  size_t seqnum_offset = 0U;
  err = crisp_checked_add_size(key_id_offset, key_id_size, &seqnum_offset);
  if (err != CRISP_OK) {
    return err;
  }

  size_t payload_offset = 0U;
  err = crisp_checked_add_size(seqnum_offset, CRISP_MESSAGE_SEQNUM_SIZE, &payload_offset);
  if (err != CRISP_OK) {
    return err;
  }
  if (payload_offset > packet.size) {
    return CRISP_ERR_INVALID_SIZE;
  }

  size_t payload_plus_icv_size = packet.size - payload_offset;
  if (payload_plus_icv_size < suite_params.icv_size) {
    return CRISP_ERR_INVALID_SIZE;
  }

  const uint64_t seqnum = crisp_read_be48(packet.data + seqnum_offset);
  if (seqnum > CRISP_SEQNUM_MAX) {
    return CRISP_ERR_OUT_OF_RANGE;
  }

  const size_t payload_size = payload_plus_icv_size - suite_params.icv_size;
  const crisp_const_byte_span_t payload = {
      .data = packet.data + payload_offset,
      .size = payload_size,
  };
  const crisp_const_byte_span_t icv = {
      .data = packet.data + payload_offset + payload_size,
      .size = suite_params.icv_size,
  };

  out_message->external_key_id_flag = external_key_id_flag;
  out_message->version = version;
  out_message->cs = cs;
  out_message->key_id_present = key_id_present;
  out_message->key_id = key_id;
  out_message->seqnum = seqnum;
  out_message->payload = payload;
  out_message->icv = icv;
  return CRISP_OK;
}

crisp_error_t crisp_build_message(const crisp_build_params_t* params,
                                 crisp_mutable_byte_span_t out_packet,
                                 size_t* out_size) {
  if (params == NULL || out_size == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (out_packet.data == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if ((params->payload.size > 0U && params->payload.data == NULL) ||
      (params->kenc.size > 0U && params->kenc.data == NULL) ||
      (params->kmac.size > 0U && params->kmac.data == NULL)) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (params->version != CRISP_VERSION_2024) {
    return CRISP_ERR_OUT_OF_RANGE;
  }
  if (params->seqnum > CRISP_SEQNUM_MAX) {
    return CRISP_ERR_OUT_OF_RANGE;
  }

  crisp_suite_params_t suite_params;
  crisp_error_t err = crisp_suite_get_params((crisp_suite_t)params->cs, &suite_params);
  if (err != CRISP_OK) {
    return err;
  }

  size_t encoded_key_id_size = 1U;
  if (params->key_id_present) {
    err = crisp_validate_key_id(params->key_id);
    if (err != CRISP_OK) {
      return err;
    }
    encoded_key_id_size = params->key_id.size;
  } else if (params->key_id.size != 0U) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  if (params->crypto == NULL || params->crypto->magma_cmac == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (suite_params.encryption_enabled && params->payload.size > 0U &&
      params->crypto->magma_ctr_xcrypt == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  size_t total_size = CRISP_MESSAGE_HEADER_PREFIX_SIZE;
  err = crisp_checked_add_size(total_size, encoded_key_id_size, &total_size);
  if (err != CRISP_OK) {
    return err;
  }
  err = crisp_checked_add_size(total_size, CRISP_MESSAGE_SEQNUM_SIZE, &total_size);
  if (err != CRISP_OK) {
    return err;
  }
  err = crisp_checked_add_size(total_size, params->payload.size, &total_size);
  if (err != CRISP_OK) {
    return err;
  }
  err = crisp_checked_add_size(total_size, suite_params.icv_size, &total_size);
  if (err != CRISP_OK) {
    return err;
  }

  if (total_size > CRISP_MAX_MESSAGE_SIZE) {
    return CRISP_ERR_INVALID_SIZE;
  }
  if (out_packet.size < total_size) {
    return CRISP_ERR_BUFFER_TOO_SMALL;
  }

  const uint16_t first16 = (uint16_t)((params->external_key_id_flag ? 0x8000U : 0x0000U) |
                                      (params->version & 0x7FFFU));
  out_packet.data[0] = (uint8_t)(first16 >> 8U);
  out_packet.data[1] = (uint8_t)(first16 & 0xFFU);
  out_packet.data[2] = params->cs;

  size_t offset = CRISP_MESSAGE_HEADER_PREFIX_SIZE;
  if (params->key_id_present) {
    (void)memcpy(out_packet.data + offset, params->key_id.data, params->key_id.size);
    offset += params->key_id.size;
  } else {
    out_packet.data[offset] = CRISP_KEY_ID_UNUSED_MARKER;
    offset += 1U;
  }

  crisp_write_be48(params->seqnum, out_packet.data + offset);
  offset += CRISP_MESSAGE_SEQNUM_SIZE;

  const size_t payload_offset = offset;
  if (params->payload.size > 0U) {
    crisp_mutable_byte_span_t payload_out = {
        .data = out_packet.data + payload_offset,
        .size = params->payload.size,
    };

    if (suite_params.encryption_enabled) {
      const uint32_t iv32 = (uint32_t)(params->seqnum & 0xFFFFFFFFU);
      err = params->crypto->magma_ctr_xcrypt(params->crypto->user_ctx, params->kenc, iv32,
                                             params->payload, payload_out);
      if (err != CRISP_OK) {
        return err;
      }
    } else {
      (void)memcpy(payload_out.data, params->payload.data, params->payload.size);
    }
  }

  const size_t icv_offset = payload_offset + params->payload.size;
  const crisp_const_byte_span_t cmac_input = {
      .data = out_packet.data,
      .size = icv_offset,
  };
  crisp_mutable_byte_span_t icv_out = {
      .data = out_packet.data + icv_offset,
      .size = suite_params.icv_size,
  };

  err = params->crypto->magma_cmac(params->crypto->user_ctx, params->kmac, cmac_input, icv_out);
  if (err != CRISP_OK) {
    return err;
  }

  *out_size = total_size;
  return CRISP_OK;
}

crisp_error_t crisp_protect(const crisp_protect_params_t* params,
                            crisp_mutable_byte_span_t out_packet,
                            size_t* out_size) {
  if (params == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  const crisp_build_params_t build_params = {
      .external_key_id_flag = params->external_key_id_flag,
      .version = CRISP_VERSION_2024,
      .cs = params->cs,
      .key_id_present = params->key_id_present,
      .seqnum = params->seqnum,
      .key_id = params->key_id,
      .payload = params->payload,
      .kenc = params->kenc,
      .kmac = params->kmac,
      .crypto = params->crypto,
  };
  return crisp_build_message(&build_params, out_packet, out_size);
}

crisp_error_t crisp_unprotect(const crisp_unprotect_params_t* params,
                              crisp_mutable_byte_span_t out_plaintext,
                              crisp_unprotect_result_t* out_result) {
  if (params == NULL || out_result == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (params->packet.data == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if ((params->kenc.size > 0U && params->kenc.data == NULL) ||
      (params->kmac.size > 0U && params->kmac.data == NULL)) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (out_plaintext.size > 0U && out_plaintext.data == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (params->crypto == NULL || params->crypto->magma_cmac == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  crisp_message_view_t view;
  crisp_error_t err = crisp_parse_message(params->packet, &view);
  if (err != CRISP_OK) {
    return err;
  }

  crisp_suite_params_t suite_params;
  err = crisp_suite_get_params((crisp_suite_t)view.cs, &suite_params);
  if (err != CRISP_OK) {
    return err;
  }
  if (view.icv.size != suite_params.icv_size) {
    return CRISP_ERR_INVALID_FORMAT;
  }

  if (suite_params.icv_size > (size_t)CRISP_INTERNAL_MAX_ICV_SIZE) {
    return CRISP_ERR_OUT_OF_RANGE;
  }

  const size_t cmac_input_size = params->packet.size - view.icv.size;
  const crisp_const_byte_span_t cmac_input = {
      .data = params->packet.data,
      .size = cmac_input_size,
  };
  uint8_t expected_icv_storage[CRISP_INTERNAL_MAX_ICV_SIZE] = {0};
  crisp_mutable_byte_span_t expected_icv_out = {
      .data = expected_icv_storage,
      .size = view.icv.size,
  };

  err = params->crypto->magma_cmac(params->crypto->user_ctx, params->kmac, cmac_input, expected_icv_out);
  if (err != CRISP_OK) {
    crisp_secure_zero(expected_icv_storage, sizeof(expected_icv_storage));
    return err;
  }
  if (!crisp_constant_time_equal(expected_icv_storage, view.icv.data, view.icv.size)) {
    crisp_secure_zero(expected_icv_storage, sizeof(expected_icv_storage));
    return CRISP_ERR_CRYPTO;
  }

  if (out_plaintext.size < view.payload.size) {
    crisp_secure_zero(expected_icv_storage, sizeof(expected_icv_storage));
    return CRISP_ERR_BUFFER_TOO_SMALL;
  }
  if (view.payload.size > 0U && out_plaintext.data == NULL) {
    crisp_secure_zero(expected_icv_storage, sizeof(expected_icv_storage));
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  if (suite_params.encryption_enabled && view.payload.size > 0U &&
      params->crypto->magma_ctr_xcrypt == NULL) {
    crisp_secure_zero(expected_icv_storage, sizeof(expected_icv_storage));
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  if (params->replay_window != NULL) {
    bool accepted = false;
    err = crisp_replay_window_check_and_update(params->replay_window, view.seqnum, &accepted);
    if (err != CRISP_OK) {
      crisp_secure_zero(expected_icv_storage, sizeof(expected_icv_storage));
      return err;
    }
    if (!accepted) {
      crisp_secure_zero(expected_icv_storage, sizeof(expected_icv_storage));
      return CRISP_ERR_REPLAY;
    }
  }

  crisp_mutable_byte_span_t plaintext_out = {
      .data = out_plaintext.data,
      .size = view.payload.size,
  };

  if (view.payload.size > 0U) {
    if (suite_params.encryption_enabled) {
      const uint32_t iv32 = (uint32_t)(view.seqnum & 0xFFFFFFFFU);
      err = params->crypto->magma_ctr_xcrypt(params->crypto->user_ctx, params->kenc, iv32, view.payload,
                                             plaintext_out);
      if (err != CRISP_OK) {
        crisp_secure_zero(expected_icv_storage, sizeof(expected_icv_storage));
        return err;
      }
    } else {
      (void)memcpy(plaintext_out.data, view.payload.data, view.payload.size);
    }
  }

  (void)memset(out_result, 0, sizeof(*out_result));
  out_result->external_key_id_flag = view.external_key_id_flag;
  out_result->version = view.version;
  out_result->cs = view.cs;
  out_result->key_id_present = view.key_id_present;
  out_result->key_id = view.key_id;
  out_result->seqnum = view.seqnum;
  out_result->plaintext = plaintext_out;
  crisp_secure_zero(expected_icv_storage, sizeof(expected_icv_storage));
  return CRISP_OK;
}

crisp_error_t crisp_unprotect_resolve(crisp_const_byte_span_t packet,
                                      const crisp_key_resolver_t* resolver,
                                      const crisp_crypto_iface_t* crypto,
                                      crisp_replay_window_t* replay_window,
                                      crisp_mutable_byte_span_t out_plaintext,
                                      crisp_unprotect_result_t* out_result) {
  if (resolver == NULL || resolver->resolve_keys == NULL || crypto == NULL || out_result == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  crisp_message_view_t view;
  crisp_error_t err = crisp_parse_message(packet, &view);
  if (err != CRISP_OK) {
    return err;
  }
  if (!view.key_id_present && !resolver->allow_key_id_unused) {
    return CRISP_ERR_INVALID_FORMAT;
  }

  const crisp_key_resolve_request_t req = {
      .external_key_id_flag = view.external_key_id_flag,
      .cs = view.cs,
      .key_id_present = view.key_id_present,
      .key_id = view.key_id,
      .seqnum = view.seqnum,
  };
  crisp_const_byte_span_t kenc = {0};
  crisp_const_byte_span_t kmac = {0};
  err = resolver->resolve_keys(resolver->user_ctx, &req, &kenc, &kmac);
  if (err != CRISP_OK) {
    return err;
  }
  if ((kenc.size > 0U && kenc.data == NULL) || (kmac.size > 0U && kmac.data == NULL)) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  const crisp_unprotect_params_t params = {
      .packet = packet,
      .kenc = kenc,
      .kmac = kmac,
      .crypto = crypto,
      .replay_window = replay_window,
  };
  return crisp_unprotect(&params, out_plaintext, out_result);
}
