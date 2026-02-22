#include <array>
#include <vector>

#include <catch2/catch_test_macros.hpp>

extern "C" {
#include "crisp/core/message.h"
#include "crisp/crypto/dummy_backend.h"
}

namespace {

crisp_crypto_iface_t make_dummy_iface(crisp_dummy_crypto_state_t* state) {
  crisp_crypto_iface_t iface{};
  crisp_dummy_crypto_iface_init(&iface, state);
  return iface;
}

std::array<uint8_t, 16> make_key_material(uint8_t start) {
  std::array<uint8_t, 16> out{};
  for (size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(start + static_cast<uint8_t>(i));
  }
  return out;
}

std::vector<uint8_t> make_raw_packet(bool external_key_id_flag,
                                     uint16_t version,
                                     uint8_t cs,
                                     const std::vector<uint8_t>& encoded_key_id,
                                     uint64_t seqnum,
                                     const std::vector<uint8_t>& payload,
                                     size_t icv_size) {
  std::vector<uint8_t> packet;
  packet.reserve(3U + encoded_key_id.size() + 6U + payload.size() + icv_size);

  const uint16_t first16 =
      static_cast<uint16_t>((external_key_id_flag ? 0x8000U : 0x0000U) | (version & 0x7FFFU));
  packet.push_back(static_cast<uint8_t>(first16 >> 8U));
  packet.push_back(static_cast<uint8_t>(first16 & 0xFFU));
  packet.push_back(cs);

  packet.insert(packet.end(), encoded_key_id.begin(), encoded_key_id.end());

  for (int shift = 40; shift >= 0; shift -= 8) {
    packet.push_back(static_cast<uint8_t>((seqnum >> shift) & 0xFFU));
  }

  packet.insert(packet.end(), payload.begin(), payload.end());

  for (size_t i = 0; i < icv_size; ++i) {
    packet.push_back(static_cast<uint8_t>(0xA0U + static_cast<uint8_t>(i)));
  }

  return packet;
}

struct TestResolverState {
  bool called = false;
  bool external_key_id_flag = false;
  uint8_t cs = 0U;
  bool key_id_present = false;
  uint64_t seqnum = 0U;
  std::vector<uint8_t> key_id{};
  crisp_const_byte_span_t kenc{};
  crisp_const_byte_span_t kmac{};
  crisp_error_t rc = CRISP_OK;
};

crisp_error_t test_resolve_keys(void* user_ctx,
                                const crisp_key_resolve_request_t* req,
                                crisp_const_byte_span_t* out_kenc,
                                crisp_const_byte_span_t* out_kmac) {
  if (user_ctx == nullptr || req == nullptr || out_kenc == nullptr || out_kmac == nullptr) {
    return CRISP_ERR_INVALID_ARGUMENT;
  }
  auto* state = static_cast<TestResolverState*>(user_ctx);
  state->called = true;
  state->external_key_id_flag = req->external_key_id_flag;
  state->cs = req->cs;
  state->key_id_present = req->key_id_present;
  state->seqnum = req->seqnum;
  state->key_id.assign(req->key_id.data, req->key_id.data + req->key_id.size);
  if (state->rc != CRISP_OK) {
    return state->rc;
  }
  *out_kenc = state->kenc;
  *out_kmac = state->kmac;
  return CRISP_OK;
}

}  // namespace

TEST_CASE("KeyId validation", "[message]") {
  const std::array<uint8_t, 1> one_byte_key_id{0x01U};
  CHECK(crisp_validate_key_id({one_byte_key_id.data(), one_byte_key_id.size()}) == CRISP_OK);

  const std::array<uint8_t, 2> two_byte_key_id{0x81U, 0xABU};
  CHECK(crisp_validate_key_id({two_byte_key_id.data(), two_byte_key_id.size()}) == CRISP_OK);

  CHECK(crisp_validate_key_id({nullptr, 0U}) == CRISP_ERR_INVALID_SIZE);

  const std::array<uint8_t, 1> key_id_unused_marker{CRISP_KEY_ID_UNUSED_MARKER};
  CHECK(crisp_validate_key_id({key_id_unused_marker.data(), key_id_unused_marker.size()}) ==
        CRISP_ERR_INVALID_FORMAT);

  const std::array<uint8_t, 2> invalid_length_key_id{0x82U, 0x11U};
  CHECK(crisp_validate_key_id({invalid_length_key_id.data(), invalid_length_key_id.size()}) ==
        CRISP_ERR_INVALID_FORMAT);
}

TEST_CASE("Version==0 allowed, Version!=0 rejected", "[message]") {
  crisp_dummy_crypto_state_t state{0x1111222233334444ULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);

  const std::array<uint8_t, 1> key_id{0x01U};
  const std::array<uint8_t, 2> payload{0x10U, 0x20U};
  const auto kenc = make_key_material(0x30U);
  const auto kmac = make_key_material(0x50U);

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet{};

  crisp_build_params_t params{};
  params.external_key_id_flag = false;
  params.version = CRISP_VERSION_2024;
  params.cs = CRISP_SUITE_CS2;
  params.key_id_present = true;
  params.seqnum = 7U;
  params.key_id = {key_id.data(), key_id.size()};
  params.payload = {payload.data(), payload.size()};
  params.kenc = {kenc.data(), kenc.size()};
  params.kmac = {kmac.data(), kmac.size()};
  params.crypto = &iface;

  size_t written = 0U;
  REQUIRE(crisp_build_message(&params, {packet.data(), packet.size()}, &written) == CRISP_OK);

  crisp_message_view_t parsed{};
  REQUIRE(crisp_parse_message({packet.data(), written}, &parsed) == CRISP_OK);
  CHECK(parsed.version == CRISP_VERSION_2024);

  params.version = 1U;
  CHECK(crisp_build_message(&params, {packet.data(), packet.size()}, &written) == CRISP_ERR_OUT_OF_RANGE);

  packet[0] = 0x00U;
  packet[1] = 0x01U;
  CHECK(crisp_parse_message({packet.data(), written}, &parsed) == CRISP_ERR_INVALID_FORMAT);
}

TEST_CASE("SeqNum BE48 encoding/decoding", "[message]") {
  crisp_dummy_crypto_state_t state{0xBADC0FFEE0DDF00DULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);

  const std::array<uint8_t, 3> key_id{0x82U, 0x11U, 0x22U};
  const std::array<uint8_t, 4> payload{0x10U, 0x20U, 0x30U, 0x40U};
  const auto kenc = make_key_material(0x30U);
  const auto kmac = make_key_material(0xA0U);

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet{};

  crisp_build_params_t params{};
  params.external_key_id_flag = true;
  params.version = CRISP_VERSION_2024;
  params.cs = CRISP_SUITE_CS1;
  params.key_id_present = true;
  params.seqnum = 0x010203040506ULL;
  params.key_id = {key_id.data(), key_id.size()};
  params.payload = {payload.data(), payload.size()};
  params.kenc = {kenc.data(), kenc.size()};
  params.kmac = {kmac.data(), kmac.size()};
  params.crypto = &iface;

  size_t written = 0U;
  REQUIRE(crisp_build_message(&params, {packet.data(), packet.size()}, &written) == CRISP_OK);

  const size_t seq_offset = CRISP_MESSAGE_HEADER_PREFIX_SIZE + key_id.size();
  REQUIRE(written > seq_offset + CRISP_MESSAGE_SEQNUM_SIZE);

  CHECK(packet[seq_offset + 0U] == 0x01U);
  CHECK(packet[seq_offset + 1U] == 0x02U);
  CHECK(packet[seq_offset + 2U] == 0x03U);
  CHECK(packet[seq_offset + 3U] == 0x04U);
  CHECK(packet[seq_offset + 4U] == 0x05U);
  CHECK(packet[seq_offset + 5U] == 0x06U);

  crisp_message_view_t parsed{};
  REQUIRE(crisp_parse_message({packet.data(), written}, &parsed) == CRISP_OK);
  CHECK(parsed.seqnum == params.seqnum);
  CHECK(parsed.external_key_id_flag);
  CHECK(parsed.key_id_present);
  CHECK(parsed.key_id.size == key_id.size());
}

TEST_CASE("KeyId decoding", "[message]") {
  SECTION("1-byte keyid (msb=0)") {
    const std::vector<uint8_t> packet =
        make_raw_packet(false, CRISP_VERSION_2024, CRISP_SUITE_CS2, {0x01U}, 3U, {0xAAU}, 4U);

    crisp_message_view_t parsed{};
    REQUIRE(crisp_parse_message({packet.data(), packet.size()}, &parsed) == CRISP_OK);
    CHECK(parsed.key_id_present);
    REQUIRE(parsed.key_id.size == 1U);
    CHECK(parsed.key_id.data[0] == 0x01U);
  }

  SECTION("multi-byte keyid (msb=1, len=2..128)") {
    const std::vector<uint8_t> short_packet =
        make_raw_packet(false, CRISP_VERSION_2024, CRISP_SUITE_CS2, {0x81U, 0x55U}, 4U, {0xBBU}, 4U);

    crisp_message_view_t parsed_short{};
    REQUIRE(crisp_parse_message({short_packet.data(), short_packet.size()}, &parsed_short) == CRISP_OK);
    CHECK(parsed_short.key_id_present);
    REQUIRE(parsed_short.key_id.size == 2U);
    CHECK(parsed_short.key_id.data[0] == 0x81U);
    CHECK(parsed_short.key_id.data[1] == 0x55U);

    std::vector<uint8_t> long_key_id(128U, 0x00U);
    long_key_id[0] = 0xFFU;
    for (size_t i = 1U; i < long_key_id.size(); ++i) {
      long_key_id[i] = static_cast<uint8_t>(i);
    }

    const std::vector<uint8_t> long_packet =
        make_raw_packet(false, CRISP_VERSION_2024, CRISP_SUITE_CS2, long_key_id, 5U, {}, 4U);

    crisp_message_view_t parsed_long{};
    REQUIRE(crisp_parse_message({long_packet.data(), long_packet.size()}, &parsed_long) == CRISP_OK);
    CHECK(parsed_long.key_id_present);
    REQUIRE(parsed_long.key_id.size == long_key_id.size());
    CHECK(parsed_long.key_id.data[0] == 0xFFU);
    CHECK(parsed_long.key_id.data[127] == 0x7FU);
  }

  SECTION("0x80 means keyid unused") {
    const std::vector<uint8_t> packet =
        make_raw_packet(true, CRISP_VERSION_2024, CRISP_SUITE_CS2, {CRISP_KEY_ID_UNUSED_MARKER}, 6U,
                        {0xCCU}, 4U);

    crisp_message_view_t parsed{};
    REQUIRE(crisp_parse_message({packet.data(), packet.size()}, &parsed) == CRISP_OK);
    CHECK(parsed.external_key_id_flag);
    CHECK_FALSE(parsed.key_id_present);
    CHECK(parsed.key_id.data == nullptr);
    CHECK(parsed.key_id.size == 0U);
  }

  SECTION("invalid keyid length encoding rejected as INVALID_FORMAT") {
    const std::array<uint8_t, 2> invalid_length_key_id{0x82U, 0x11U};
    CHECK(crisp_validate_key_id({invalid_length_key_id.data(), invalid_length_key_id.size()}) ==
          CRISP_ERR_INVALID_FORMAT);
  }

  SECTION("truncated keyid rejected as INVALID_SIZE") {
    const std::vector<uint8_t> invalid_packet =
        make_raw_packet(false, CRISP_VERSION_2024, CRISP_SUITE_CS2, {0xFFU}, 1U, {}, 4U);

    crisp_message_view_t parsed{};
    CHECK(crisp_parse_message({invalid_packet.data(), invalid_packet.size()}, &parsed) ==
          CRISP_ERR_INVALID_SIZE);
  }
}

TEST_CASE("Message size boundary at 2048 bytes", "[message]") {
  crisp_dummy_crypto_state_t state{0x0102030405060708ULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);

  const auto kenc = make_key_material(0x10U);
  const auto kmac = make_key_material(0x20U);

  const size_t payload_ok_size =
      CRISP_MAX_MESSAGE_SIZE - CRISP_MESSAGE_HEADER_PREFIX_SIZE - 1U - CRISP_MESSAGE_SEQNUM_SIZE - 4U;
  std::vector<uint8_t> payload_ok(payload_ok_size, 0x5AU);

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet{};

  crisp_build_params_t params{};
  params.external_key_id_flag = false;
  params.version = CRISP_VERSION_2024;
  params.cs = CRISP_SUITE_CS2;
  params.key_id_present = false;
  params.seqnum = 17U;
  params.payload = {payload_ok.data(), payload_ok.size()};
  params.kenc = {kenc.data(), kenc.size()};
  params.kmac = {kmac.data(), kmac.size()};
  params.crypto = &iface;

  size_t written = 0U;
  REQUIRE(crisp_build_message(&params, {packet.data(), packet.size()}, &written) == CRISP_OK);
  CHECK(written == CRISP_MAX_MESSAGE_SIZE);

  std::vector<uint8_t> payload_too_big(payload_ok_size + 1U, 0x5AU);
  params.payload = {payload_too_big.data(), payload_too_big.size()};
  CHECK(crisp_build_message(&params, {packet.data(), packet.size()}, &written) ==
        CRISP_ERR_INVALID_SIZE);
}

TEST_CASE("Parse/build roundtrip", "[message]") {
  crisp_dummy_crypto_state_t state{0xABCD123400001111ULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);

  const std::array<uint8_t, 4> key_id{0x83U, 0x22U, 0x23U, 0x24U};
  const std::array<uint8_t, 8> payload{0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U, 0xA6U, 0xA7U, 0xA8U};
  const auto kenc = make_key_material(0x33U);
  const auto kmac = make_key_material(0x44U);

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet1{};
  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet2{};

  crisp_build_params_t p1{};
  p1.external_key_id_flag = false;
  p1.version = CRISP_VERSION_2024;
  p1.cs = CRISP_SUITE_CS2;
  p1.key_id_present = true;
  p1.seqnum = 0x000000010203ULL;
  p1.key_id = {key_id.data(), key_id.size()};
  p1.payload = {payload.data(), payload.size()};
  p1.kenc = {kenc.data(), kenc.size()};
  p1.kmac = {kmac.data(), kmac.size()};
  p1.crypto = &iface;

  size_t written1 = 0U;
  REQUIRE(crisp_build_message(&p1, {packet1.data(), packet1.size()}, &written1) == CRISP_OK);

  crisp_message_view_t parsed{};
  REQUIRE(crisp_parse_message({packet1.data(), written1}, &parsed) == CRISP_OK);

  crisp_build_params_t p2{};
  p2.external_key_id_flag = parsed.external_key_id_flag;
  p2.version = parsed.version;
  p2.cs = parsed.cs;
  p2.key_id_present = parsed.key_id_present;
  p2.seqnum = parsed.seqnum;
  p2.key_id = parsed.key_id;
  p2.payload = parsed.payload;
  p2.kenc = {kenc.data(), kenc.size()};
  p2.kmac = {kmac.data(), kmac.size()};
  p2.crypto = &iface;

  size_t written2 = 0U;
  REQUIRE(crisp_build_message(&p2, {packet2.data(), packet2.size()}, &written2) == CRISP_OK);
  REQUIRE(written2 == written1);

  for (size_t i = 0; i < written1; ++i) {
    CHECK(packet1[i] == packet2[i]);
  }
}

TEST_CASE("Unprotect rejects ICV mismatch", "[message]") {
  crisp_dummy_crypto_state_t state{0x00ABCDEF12345678ULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);
  const auto kenc = make_key_material(0x11U);
  const auto kmac = make_key_material(0x22U);

  const std::array<uint8_t, 1> key_id{0x01U};
  const std::array<uint8_t, 5> payload{0x10U, 0x20U, 0x30U, 0x40U, 0x50U};
  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet{};

  crisp_protect_params_t protect{};
  protect.external_key_id_flag = false;
  protect.cs = CRISP_SUITE_CS2;
  protect.key_id_present = true;
  protect.seqnum = 0x10203U;
  protect.key_id = {key_id.data(), key_id.size()};
  protect.payload = {payload.data(), payload.size()};
  protect.kenc = {kenc.data(), kenc.size()};
  protect.kmac = {kmac.data(), kmac.size()};
  protect.crypto = &iface;

  size_t written = 0U;
  REQUIRE(crisp_protect(&protect, {packet.data(), packet.size()}, &written) == CRISP_OK);
  REQUIRE(written > 0U);

  packet[written - 1U] ^= 0x01U;

  std::array<uint8_t, 16> plaintext_out{};
  plaintext_out.fill(0xEEU);
  crisp_unprotect_params_t unprotect{};
  unprotect.packet = {packet.data(), written};
  unprotect.kenc = {kenc.data(), kenc.size()};
  unprotect.kmac = {kmac.data(), kmac.size()};
  unprotect.crypto = &iface;
  unprotect.replay_window = nullptr;

  crisp_unprotect_result_t result{};
  CHECK(crisp_unprotect(&unprotect, {plaintext_out.data(), plaintext_out.size()}, &result) ==
        CRISP_ERR_CRYPTO);
  for (uint8_t byte : plaintext_out) {
    CHECK(byte == 0xEEU);
  }
}

TEST_CASE("Protect/unprotect encrypt-decrypt roundtrip", "[message]") {
  crisp_dummy_crypto_state_t state{0x1234567890ABCDEFULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);
  const auto kenc = make_key_material(0x31U);
  const auto kmac = make_key_material(0x41U);

  const std::array<uint8_t, 2> key_id{0x81U, 0x44U};
  const std::array<uint8_t, 8> payload{0x01U, 0x03U, 0x05U, 0x07U, 0x09U, 0x0BU, 0x0DU, 0x0FU};
  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet{};

  crisp_protect_params_t protect{};
  protect.external_key_id_flag = true;
  protect.cs = CRISP_SUITE_CS1;
  protect.key_id_present = true;
  protect.seqnum = 0x010203040506ULL;
  protect.key_id = {key_id.data(), key_id.size()};
  protect.payload = {payload.data(), payload.size()};
  protect.kenc = {kenc.data(), kenc.size()};
  protect.kmac = {kmac.data(), kmac.size()};
  protect.crypto = &iface;

  size_t written = 0U;
  REQUIRE(crisp_protect(&protect, {packet.data(), packet.size()}, &written) == CRISP_OK);

  crisp_message_view_t parsed{};
  REQUIRE(crisp_parse_message({packet.data(), written}, &parsed) == CRISP_OK);
  REQUIRE(parsed.payload.size == payload.size());

  bool has_diff = false;
  for (size_t i = 0U; i < payload.size(); ++i) {
    if (parsed.payload.data[i] != payload[i]) {
      has_diff = true;
      break;
    }
  }
  CHECK(has_diff);

  std::array<uint8_t, 64> plaintext_out{};
  crisp_unprotect_params_t unprotect{};
  unprotect.packet = {packet.data(), written};
  unprotect.kenc = {kenc.data(), kenc.size()};
  unprotect.kmac = {kmac.data(), kmac.size()};
  unprotect.crypto = &iface;
  unprotect.replay_window = nullptr;

  crisp_unprotect_result_t result{};
  REQUIRE(crisp_unprotect(&unprotect, {plaintext_out.data(), plaintext_out.size()}, &result) == CRISP_OK);
  REQUIRE(result.plaintext.size == payload.size());
  CHECK(result.external_key_id_flag);
  CHECK(result.cs == CRISP_SUITE_CS1);
  CHECK(result.seqnum == protect.seqnum);
  CHECK(result.key_id_present);
  CHECK(result.key_id.size == key_id.size());

  for (size_t i = 0U; i < payload.size(); ++i) {
    CHECK(plaintext_out[i] == payload[i]);
  }
}

TEST_CASE("Unprotect rejects replayed sequence number", "[message]") {
  crisp_dummy_crypto_state_t state{0x9988776655443322ULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);
  const auto kenc = make_key_material(0x51U);
  const auto kmac = make_key_material(0x61U);
  const std::array<uint8_t, 3> payload{0xA1U, 0xB2U, 0xC3U};

  crisp_replay_window_t replay{};
  REQUIRE(crisp_replay_window_init(&replay, 32U) == CRISP_OK);

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet1{};
  crisp_protect_params_t p1{};
  p1.external_key_id_flag = false;
  p1.cs = CRISP_SUITE_CS2;
  p1.key_id_present = false;
  p1.seqnum = 100U;
  p1.payload = {payload.data(), payload.size()};
  p1.kenc = {kenc.data(), kenc.size()};
  p1.kmac = {kmac.data(), kmac.size()};
  p1.crypto = &iface;

  size_t written1 = 0U;
  REQUIRE(crisp_protect(&p1, {packet1.data(), packet1.size()}, &written1) == CRISP_OK);

  std::array<uint8_t, 32> plaintext_out{};
  crisp_unprotect_params_t up1{};
  up1.packet = {packet1.data(), written1};
  up1.kenc = {kenc.data(), kenc.size()};
  up1.kmac = {kmac.data(), kmac.size()};
  up1.crypto = &iface;
  up1.replay_window = &replay;

  crisp_unprotect_result_t result{};
  REQUIRE(crisp_unprotect(&up1, {plaintext_out.data(), plaintext_out.size()}, &result) == CRISP_OK);
  CHECK(result.seqnum == 100U);

  plaintext_out.fill(0xA5U);
  CHECK(crisp_unprotect(&up1, {plaintext_out.data(), plaintext_out.size()}, &result) ==
        CRISP_ERR_REPLAY);
  for (uint8_t byte : plaintext_out) {
    CHECK(byte == 0xA5U);
  }

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet2{};
  crisp_protect_params_t p2 = p1;
  p2.seqnum = 101U;

  size_t written2 = 0U;
  REQUIRE(crisp_protect(&p2, {packet2.data(), packet2.size()}, &written2) == CRISP_OK);

  crisp_unprotect_params_t up2 = up1;
  up2.packet = {packet2.data(), written2};
  REQUIRE(crisp_unprotect(&up2, {plaintext_out.data(), plaintext_out.size()}, &result) == CRISP_OK);
  CHECK(result.seqnum == 101U);
}

TEST_CASE("ICV mismatch does not update replay window", "[message]") {
  crisp_dummy_crypto_state_t state{0xCAFEBABE12344321ULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);
  const auto kenc = make_key_material(0x91U);
  const auto kmac = make_key_material(0xA1U);
  const std::array<uint8_t, 4> payload{0x10U, 0x22U, 0x34U, 0x46U};

  crisp_protect_params_t protect{};
  protect.external_key_id_flag = false;
  protect.cs = CRISP_SUITE_CS2;
  protect.key_id_present = false;
  protect.seqnum = 777U;
  protect.payload = {payload.data(), payload.size()};
  protect.kenc = {kenc.data(), kenc.size()};
  protect.kmac = {kmac.data(), kmac.size()};
  protect.crypto = &iface;

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet{};
  size_t written = 0U;
  REQUIRE(crisp_protect(&protect, {packet.data(), packet.size()}, &written) == CRISP_OK);

  std::vector<uint8_t> tampered(packet.data(), packet.data() + written);
  tampered.back() ^= 0x55U;

  crisp_replay_window_t replay{};
  REQUIRE(crisp_replay_window_init(&replay, 32U) == CRISP_OK);

  crisp_unprotect_params_t bad{};
  bad.packet = {tampered.data(), tampered.size()};
  bad.kenc = {kenc.data(), kenc.size()};
  bad.kmac = {kmac.data(), kmac.size()};
  bad.crypto = &iface;
  bad.replay_window = &replay;

  std::array<uint8_t, 16> out{};
  out.fill(0x7BU);
  crisp_unprotect_result_t result{};
  CHECK(crisp_unprotect(&bad, {out.data(), out.size()}, &result) == CRISP_ERR_CRYPTO);

  crisp_unprotect_params_t good = bad;
  good.packet = {packet.data(), written};
  REQUIRE(crisp_unprotect(&good, {out.data(), out.size()}, &result) == CRISP_OK);
  CHECK(result.seqnum == protect.seqnum);
}

TEST_CASE("Unprotect resolve calls resolver with correct metadata", "[message]") {
  crisp_dummy_crypto_state_t state{0xCCDD001122334455ULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);
  const auto kenc = make_key_material(0xB1U);
  const auto kmac = make_key_material(0xC1U);

  const std::array<uint8_t, 3> key_id{0x82U, 0xAAU, 0xBBU};
  const std::array<uint8_t, 3> payload{0x01U, 0x02U, 0x03U};
  const uint64_t seqnum = 0x001122334455ULL;

  crisp_protect_params_t protect{};
  protect.external_key_id_flag = true;
  protect.cs = CRISP_SUITE_CS1;
  protect.key_id_present = true;
  protect.seqnum = seqnum;
  protect.key_id = {key_id.data(), key_id.size()};
  protect.payload = {payload.data(), payload.size()};
  protect.kenc = {kenc.data(), kenc.size()};
  protect.kmac = {kmac.data(), kmac.size()};
  protect.crypto = &iface;

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet{};
  size_t written = 0U;
  REQUIRE(crisp_protect(&protect, {packet.data(), packet.size()}, &written) == CRISP_OK);

  TestResolverState resolver_state{};
  resolver_state.kenc = {kenc.data(), kenc.size()};
  resolver_state.kmac = {kmac.data(), kmac.size()};
  crisp_key_resolver_t resolver{};
  resolver.user_ctx = &resolver_state;
  resolver.resolve_keys = test_resolve_keys;
  resolver.allow_key_id_unused = false;

  std::array<uint8_t, 16> out{};
  crisp_unprotect_result_t result{};
  REQUIRE(crisp_unprotect_resolve({packet.data(), written}, &resolver, &iface, nullptr,
                                  {out.data(), out.size()}, &result) == CRISP_OK);
  REQUIRE(resolver_state.called);
  CHECK(resolver_state.external_key_id_flag);
  CHECK(resolver_state.cs == CRISP_SUITE_CS1);
  CHECK(resolver_state.key_id_present);
  CHECK(resolver_state.seqnum == seqnum);
  REQUIRE(resolver_state.key_id.size() == key_id.size());
  for (size_t i = 0U; i < key_id.size(); ++i) {
    CHECK(resolver_state.key_id[i] == key_id[i]);
  }
}

TEST_CASE("Unprotect resolve returns configured no-key error", "[message]") {
  crisp_dummy_crypto_state_t state{0xDEADBEEF00001111ULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);
  const auto kenc = make_key_material(0xD1U);
  const auto kmac = make_key_material(0xE1U);
  const std::array<uint8_t, 2> payload{0xFAU, 0xCEU};

  crisp_protect_params_t protect{};
  protect.external_key_id_flag = false;
  protect.cs = CRISP_SUITE_CS2;
  protect.key_id_present = true;
  const std::array<uint8_t, 1> key_id{0x11U};
  protect.key_id = {key_id.data(), key_id.size()};
  protect.seqnum = 99U;
  protect.payload = {payload.data(), payload.size()};
  protect.kenc = {kenc.data(), kenc.size()};
  protect.kmac = {kmac.data(), kmac.size()};
  protect.crypto = &iface;

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet{};
  size_t written = 0U;
  REQUIRE(crisp_protect(&protect, {packet.data(), packet.size()}, &written) == CRISP_OK);

  TestResolverState resolver_state{};
  resolver_state.rc = CRISP_ERR_INVALID_FORMAT;
  crisp_key_resolver_t resolver{};
  resolver.user_ctx = &resolver_state;
  resolver.resolve_keys = test_resolve_keys;
  resolver.allow_key_id_unused = false;

  std::array<uint8_t, 8> out{};
  out.fill(0x66U);
  crisp_unprotect_result_t result{};
  CHECK(crisp_unprotect_resolve({packet.data(), written}, &resolver, &iface, nullptr,
                                {out.data(), out.size()}, &result) == CRISP_ERR_INVALID_FORMAT);
  REQUIRE(resolver_state.called);
  for (uint8_t b : out) {
    CHECK(b == 0x66U);
  }
}

TEST_CASE("Unprotect resolve rejects unused key id by policy", "[message]") {
  crisp_dummy_crypto_state_t state{0xABABABAB01020304ULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);
  const auto kenc = make_key_material(0x21U);
  const auto kmac = make_key_material(0x31U);
  const std::array<uint8_t, 1> payload{0x9AU};

  crisp_protect_params_t protect{};
  protect.external_key_id_flag = false;
  protect.cs = CRISP_SUITE_CS2;
  protect.key_id_present = false;
  protect.seqnum = 88U;
  protect.payload = {payload.data(), payload.size()};
  protect.kenc = {kenc.data(), kenc.size()};
  protect.kmac = {kmac.data(), kmac.size()};
  protect.crypto = &iface;

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet{};
  size_t written = 0U;
  REQUIRE(crisp_protect(&protect, {packet.data(), packet.size()}, &written) == CRISP_OK);

  TestResolverState resolver_state{};
  resolver_state.kenc = {kenc.data(), kenc.size()};
  resolver_state.kmac = {kmac.data(), kmac.size()};
  crisp_key_resolver_t resolver{};
  resolver.user_ctx = &resolver_state;
  resolver.resolve_keys = test_resolve_keys;
  resolver.allow_key_id_unused = false;

  std::array<uint8_t, 8> out{};
  crisp_unprotect_result_t result{};
  CHECK(crisp_unprotect_resolve({packet.data(), written}, &resolver, &iface, nullptr,
                                {out.data(), out.size()}, &result) == CRISP_ERR_INVALID_FORMAT);
  CHECK_FALSE(resolver_state.called);
}

TEST_CASE("Unprotect rejects too small output buffer without modifying it", "[message]") {
  crisp_dummy_crypto_state_t state{0x13572468ABCDEF01ULL};
  const crisp_crypto_iface_t iface = make_dummy_iface(&state);
  const auto kenc = make_key_material(0x71U);
  const auto kmac = make_key_material(0x81U);
  const std::array<uint8_t, 5> payload{0x11U, 0x22U, 0x33U, 0x44U, 0x55U};

  std::array<uint8_t, CRISP_MAX_MESSAGE_SIZE> packet{};
  crisp_protect_params_t protect{};
  protect.external_key_id_flag = false;
  protect.cs = CRISP_SUITE_CS2;
  protect.key_id_present = false;
  protect.seqnum = 7U;
  protect.payload = {payload.data(), payload.size()};
  protect.kenc = {kenc.data(), kenc.size()};
  protect.kmac = {kmac.data(), kmac.size()};
  protect.crypto = &iface;

  size_t written = 0U;
  REQUIRE(crisp_protect(&protect, {packet.data(), packet.size()}, &written) == CRISP_OK);

  crisp_unprotect_params_t unprotect{};
  unprotect.packet = {packet.data(), written};
  unprotect.kenc = {kenc.data(), kenc.size()};
  unprotect.kmac = {kmac.data(), kmac.size()};
  unprotect.crypto = &iface;
  unprotect.replay_window = nullptr;

  std::array<uint8_t, 4> too_small{};
  too_small.fill(0x5AU);
  crisp_unprotect_result_t result{};
  CHECK(crisp_unprotect(&unprotect, {too_small.data(), too_small.size()}, &result) ==
        CRISP_ERR_BUFFER_TOO_SMALL);
  for (uint8_t byte : too_small) {
    CHECK(byte == 0x5AU);
  }
}

TEST_CASE("Parse rejects packet larger than 2048", "[message]") {
  std::vector<uint8_t> oversized(CRISP_MAX_MESSAGE_SIZE + 1U, 0x00U);
  crisp_message_view_t parsed{};
  CHECK(crisp_parse_message({oversized.data(), oversized.size()}, &parsed) == CRISP_ERR_INVALID_SIZE);
}
