#pragma once
#include "common.h"

// ----------------------------------------------------------------
// LSA decryption (lsass memory path)
// ----------------------------------------------------------------
Bytes lsa_decrypt(std::span<const uint8_t> enc,
                  std::span<const uint8_t> aes_key,
                  std::span<const uint8_t> des_key,
                  std::span<const uint8_t> iv);

// ----------------------------------------------------------------
// Hash functions via CNG
// ----------------------------------------------------------------
Bytes md5_hash(std::span<const uint8_t> data);
Bytes sha256_hash(std::span<const uint8_t> data);

// ----------------------------------------------------------------
// Symmetric ciphers via CNG
// ----------------------------------------------------------------
Bytes rc4_decrypt(std::span<const uint8_t> key, std::span<const uint8_t> data);
Bytes aes128_cbc_decrypt(std::span<const uint8_t> key,
                         std::span<const uint8_t> iv,
                         std::span<const uint8_t> data);
Bytes des_ecb_decrypt(std::span<const uint8_t> key8,
                      std::span<const uint8_t> data8);

// ----------------------------------------------------------------
// DES key expansion: 7 bytes -> 8 bytes with parity
// ----------------------------------------------------------------
Bytes des_expand_key(std::span<const uint8_t> key7);

// ----------------------------------------------------------------
// RID-to-DES-keys helper for SAM hash decryption
// ----------------------------------------------------------------
std::pair<Bytes, Bytes> rid_to_des_keys(uint32_t rid);
