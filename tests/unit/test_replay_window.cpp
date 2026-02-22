#include <catch2/catch_test_macros.hpp>

extern "C" {
#include "crisp/core/replay_window.h"
}

TEST_CASE("Replay window initialization", "[replay]") {
  crisp_replay_window_t window{};

  CHECK(crisp_replay_window_init(nullptr, 64U) == CRISP_ERR_INVALID_ARGUMENT);
  CHECK(crisp_replay_window_init(&window, 0U) == CRISP_ERR_OUT_OF_RANGE);
  CHECK(crisp_replay_window_init(&window, 257U) == CRISP_ERR_OUT_OF_RANGE);
  CHECK(crisp_replay_window_init(&window, 64U) == CRISP_OK);
}

TEST_CASE("Replay window check/update behavior", "[replay]") {
  crisp_replay_window_t window{};
  REQUIRE(crisp_replay_window_init(&window, 4U) == CRISP_OK);

  bool accepted = false;

  REQUIRE(crisp_replay_window_check_and_update(&window, 10U, &accepted) == CRISP_OK);
  CHECK(accepted);

  REQUIRE(crisp_replay_window_check_and_update(&window, 9U, &accepted) == CRISP_OK);
  CHECK(accepted);

  REQUIRE(crisp_replay_window_check_and_update(&window, 8U, &accepted) == CRISP_OK);
  CHECK(accepted);

  REQUIRE(crisp_replay_window_check_and_update(&window, 7U, &accepted) == CRISP_OK);
  CHECK(accepted);

  REQUIRE(crisp_replay_window_check_and_update(&window, 6U, &accepted) == CRISP_OK);
  CHECK_FALSE(accepted);

  REQUIRE(crisp_replay_window_check_and_update(&window, 9U, &accepted) == CRISP_OK);
  CHECK_FALSE(accepted);

  REQUIRE(crisp_replay_window_check_and_update(&window, 11U, &accepted) == CRISP_OK);
  CHECK(accepted);

  REQUIRE(crisp_replay_window_check_and_update(&window, 10U, &accepted) == CRISP_OK);
  CHECK_FALSE(accepted);
}

TEST_CASE("Replay window validates SeqNum range", "[replay]") {
  crisp_replay_window_t window{};
  REQUIRE(crisp_replay_window_init(&window, 32U) == CRISP_OK);

  bool accepted = false;
  CHECK(crisp_replay_window_check_and_update(&window, CRISP_SEQNUM_MAX + 1ULL, &accepted) ==
        CRISP_ERR_OUT_OF_RANGE);
}
