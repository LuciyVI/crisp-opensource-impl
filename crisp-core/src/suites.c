#include "crisp/core/suites.h"

crisp_error_t crisp_suite_get_params(crisp_suite_t suite, crisp_suite_params_t* out_params) {
  if (out_params == NULL) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }

  switch (suite) {
    case CRISP_SUITE_CS1:
      out_params->icv_size = 4U;
      out_params->encryption_enabled = true;
      return CRISP_OK;
    case CRISP_SUITE_CS2:
      out_params->icv_size = 4U;
      out_params->encryption_enabled = false;
      return CRISP_OK;
    case CRISP_SUITE_CS3:
      out_params->icv_size = 8U;
      out_params->encryption_enabled = true;
      return CRISP_OK;
    case CRISP_SUITE_CS4:
      out_params->icv_size = 8U;
      out_params->encryption_enabled = false;
      return CRISP_OK;
    default:
      return CRISP_ERR_UNSUPPORTED_SUITE;
  }
}
