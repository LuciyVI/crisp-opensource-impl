#include <catch2/catch_test_macros.hpp>

extern "C" {
#include "crisp/core/suites.h"
}

TEST_CASE("Suite parameters", "[suite]") {
  crisp_suite_params_t params{};

  REQUIRE(crisp_suite_get_params(CRISP_SUITE_CS1, &params) == CRISP_OK);
  CHECK(params.icv_size == 4U);
  CHECK(params.encryption_enabled);

  REQUIRE(crisp_suite_get_params(CRISP_SUITE_CS2, &params) == CRISP_OK);
  CHECK(params.icv_size == 4U);
  CHECK_FALSE(params.encryption_enabled);

  REQUIRE(crisp_suite_get_params(CRISP_SUITE_CS3, &params) == CRISP_OK);
  CHECK(params.icv_size == 8U);
  CHECK(params.encryption_enabled);

  REQUIRE(crisp_suite_get_params(CRISP_SUITE_CS4, &params) == CRISP_OK);
  CHECK(params.icv_size == 8U);
  CHECK_FALSE(params.encryption_enabled);

  CHECK(crisp_suite_get_params(static_cast<crisp_suite_t>(0), &params) == CRISP_ERR_UNSUPPORTED_SUITE);
  CHECK(crisp_suite_get_params(static_cast<crisp_suite_t>(5), &params) == CRISP_ERR_UNSUPPORTED_SUITE);
}
