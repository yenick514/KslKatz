#include "crypto.h"
#include <bcrypt.h>
#include <algorithm>
#include <array>

#pragma comment(lib, "bcrypt.lib")

// ================================================================
// RAII wrappers
// ================================================================

struct BcryptAlg {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~BcryptAlg() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};

struct BcryptKey {
    BCRYPT_KEY_HANDLE h = nullptr;
    ~BcryptKey() { if (h) BCryptDestroyKey(h); }
};

struct BcryptHash {
    BCRYPT_HASH_HANDLE h = nullptr;
    ~BcryptHash() { if (h) BCryptDestroyHash(h); }
};

// ================================================================
// Hash functions
// ================================================================

static Bytes cng_hash(const wchar_t* alg_id, size_t digest_len, std::span<const uint8_t> data) {
    BcryptAlg alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, alg_id, nullptr, 0)))
        return {};

    BcryptHash hash;
    if (!BCRYPT_SUCCESS(BCryptCreateHash(alg.h, &hash.h, nullptr, 0, nullptr, 0, 0)))
        return {};

    if (!BCRYPT_SUCCESS(BCryptHashData(hash.h, const_cast<PUCHAR>(data.data()),
                                       static_cast<ULONG>(data.size()), 0)))
        return {};

    Bytes digest(digest_len, 0);
    if (!BCRYPT_SUCCESS(BCryptFinishHash(hash.h, digest.data(),
                                         static_cast<ULONG>(digest_len), 0)))
        return {};

    return digest;
}

Bytes md5_hash(std::span<const uint8_t> data) {
    return cng_hash(BCRYPT_MD5_ALGORITHM, 16, data);
}

Bytes sha256_hash(std::span<const uint8_t> data) {
    return cng_hash(BCRYPT_SHA256_ALGORITHM, 32, data);
}

// ================================================================
// RC4 decryption
// ================================================================

Bytes rc4_decrypt(std::span<const uint8_t> key, std::span<const uint8_t> data) {
    BcryptAlg alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_RC4_ALGORITHM, nullptr, 0)))
        return {};

    BcryptKey bkey;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg.h, &bkey.h, nullptr, 0,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0)))
        return {};

    Bytes output(data.size(), 0);
    ULONG result_len = 0;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(bkey.h,
        const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()),
        nullptr, nullptr, 0,
        output.data(), static_cast<ULONG>(output.size()),
        &result_len, 0)))
        return {};

    output.resize(result_len);
    return output;
}

// ================================================================
// AES-128-CBC decryption
// ================================================================

Bytes aes128_cbc_decrypt(std::span<const uint8_t> key,
                         std::span<const uint8_t> iv,
                         std::span<const uint8_t> data) {
    BcryptAlg alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return {};

    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_CBC)), 0)))
        return {};

    BcryptKey bkey;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg.h, &bkey.h, nullptr, 0,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0)))
        return {};

    // IV copy (BCryptDecrypt modifies it)
    Bytes iv_copy(iv.begin(), iv.end());
    iv_copy.resize(16, 0);

    Bytes output(data.size(), 0);
    ULONG result_len = 0;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(bkey.h,
        const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()),
        nullptr,
        iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
        output.data(), static_cast<ULONG>(output.size()),
        &result_len, 0)))
        return {};

    output.resize(result_len);
    return output;
}

// ================================================================
// DES-ECB single block decryption (8 bytes)
// ================================================================

Bytes des_ecb_decrypt(std::span<const uint8_t> key8,
                      std::span<const uint8_t> data8) {
    BcryptAlg alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_DES_ALGORITHM, nullptr, 0)))
        return {};

    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
        static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_ECB)), 0)))
        return {};

    BcryptKey bkey;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg.h, &bkey.h, nullptr, 0,
        const_cast<PUCHAR>(key8.data()), static_cast<ULONG>(key8.size()), 0)))
        return {};

    Bytes output(8, 0);
    ULONG result_len = 0;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(bkey.h,
        const_cast<PUCHAR>(data8.data()), static_cast<ULONG>(data8.size()),
        nullptr, nullptr, 0,
        output.data(), 8, &result_len, 0)))
        return {};

    return output;
}

// ================================================================
// DES key expansion: 7 bytes -> 8 bytes with parity bits
// ================================================================

Bytes des_expand_key(std::span<const uint8_t> key7) {
    if (key7.size() < 7) return {};

    Bytes key8(8);
    key8[0] = key7[0] >> 1;
    key8[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2);
    key8[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3);
    key8[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4);
    key8[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5);
    key8[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6);
    key8[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7);
    key8[7] = key7[6] & 0x7F;

    // Set parity bits (odd parity)
    for (auto& b : key8)
        b = (b << 1) & 0xFE;

    return key8;
}

// ================================================================
// RID -> two DES keys for SAM hash double-DES
// ================================================================

std::pair<Bytes, Bytes> rid_to_des_keys(uint32_t rid) {
    uint8_t r[4];
    std::memcpy(r, &rid, 4);

    // First 7-byte key derived from RID bytes
    uint8_t k1[7] = { r[0], r[1], r[2], r[3], r[0], r[1], r[2] };
    // Second 7-byte key (shifted by one)
    uint8_t k2[7] = { r[3], r[0], r[1], r[2], r[3], r[0], r[1] };

    return { des_expand_key(k1), des_expand_key(k2) };
}

// ================================================================
// AES-CFB128 decrypt (manual ECB+XOR, BCrypt only supports CFB8)
// ================================================================

static Bytes aes_cfb128_decrypt(std::span<const uint8_t> ct,
                                std::span<const uint8_t> key,
                                std::span<const uint8_t> iv) {
    BcryptAlg alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_AES_ALGORITHM, nullptr, 0)))
        return {};

    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_ECB)),
        static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_ECB)), 0)))
        return {};

    BcryptKey bkey;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg.h, &bkey.h, nullptr, 0,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0)))
        return {};

    Bytes plaintext;
    plaintext.reserve(ct.size());

    std::array<uint8_t, 16> feedback{};
    std::memcpy(feedback.data(), iv.data(), std::min<size_t>(iv.size(), 16));

    for (size_t off = 0; off < ct.size(); off += 16) {
        std::array<uint8_t, 16> encrypted{};
        std::array<uint8_t, 16> fb_copy = feedback;
        ULONG result_len = 0;
        if (!BCRYPT_SUCCESS(BCryptEncrypt(bkey.h, fb_copy.data(), 16, nullptr,
            nullptr, 0, encrypted.data(), 16, &result_len, 0)))
            return {};

        size_t block_len = std::min<size_t>(16, ct.size() - off);
        for (size_t i = 0; i < block_len; ++i)
            plaintext.push_back(encrypted[i] ^ ct[off + i]);

        std::memset(feedback.data(), 0, 16);
        std::memcpy(feedback.data(), ct.data() + off, block_len);
    }

    return plaintext;
}

// ================================================================
// 3DES-CBC decryption
// ================================================================

static Bytes des3_cbc_decrypt(std::span<const uint8_t> ct,
                              std::span<const uint8_t> key,
                              std::span<const uint8_t> iv8) {
    BcryptAlg alg;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg.h, BCRYPT_3DES_ALGORITHM, nullptr, 0)))
        return {};

    if (!BCRYPT_SUCCESS(BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        static_cast<ULONG>(sizeof(BCRYPT_CHAIN_MODE_CBC)), 0)))
        return {};

    BcryptKey bkey;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(alg.h, &bkey.h, nullptr, 0,
        const_cast<PUCHAR>(key.data()), static_cast<ULONG>(key.size()), 0)))
        return {};

    std::array<uint8_t, 8> iv_copy{};
    std::memcpy(iv_copy.data(), iv8.data(), std::min<size_t>(iv8.size(), 8));

    Bytes plaintext(ct.size(), 0);
    ULONG result_len = 0;
    if (!BCRYPT_SUCCESS(BCryptDecrypt(bkey.h,
        const_cast<PUCHAR>(ct.data()), static_cast<ULONG>(ct.size()),
        nullptr,
        iv_copy.data(), static_cast<ULONG>(iv_copy.size()),
        plaintext.data(), static_cast<ULONG>(plaintext.size()),
        &result_len, 0)))
        return {};

    plaintext.resize(result_len);
    return plaintext;
}

// ================================================================
// LSA decryption dispatcher
// ================================================================

Bytes lsa_decrypt(std::span<const uint8_t> enc,
                  std::span<const uint8_t> aes_key,
                  std::span<const uint8_t> des_key,
                  std::span<const uint8_t> iv) {
    if (enc.empty()) return {};

    if (enc.size() % 8 != 0) {
        return aes_cfb128_decrypt(enc, aes_key, iv);
    } else {
        auto iv8 = iv.subspan(0, std::min<size_t>(iv.size(), 8));
        return des3_cbc_decrypt(enc, des_key, iv8);
    }
}
