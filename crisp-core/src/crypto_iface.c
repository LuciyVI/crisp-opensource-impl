#include "crisp/crypto/iface.h"

crisp_error_t crisp_derive_kenc_kmac(const crisp_crypto_iface_t* iface,
                                     crisp_const_byte_span_t master_key,
                                     crisp_const_byte_span_t salt,
                                     crisp_mutable_byte_span_t out_kenc,
                                     crisp_mutable_byte_span_t out_kmac) {
  if (iface == NULL || iface->derive_kenc_kmac == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  if ((master_key.size > 0U && master_key.data == NULL) || (salt.size > 0U && salt.data == NULL) ||
      (out_kenc.size > 0U && out_kenc.data == NULL) ||
      (out_kmac.size > 0U && out_kmac.data == NULL)) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  return iface->derive_kenc_kmac(iface->user_ctx, master_key, salt, out_kenc, out_kmac);
}
