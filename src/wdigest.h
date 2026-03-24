#pragma once
#include "common.h"
#include "memory.h"
#include "lsa.h"

// Extract WDigest cleartext passwords from lsass memory.
// Uses local LoadLibraryA("wdigest.dll") for signature scan,
// then remote proc_read for actual credential data.
// Requires LSA encryption keys (same as MSV1_0).
std::vector<WDigestCredential> extract_wdigest_creds(
    HANDLE h, uint64_t dtb,
    uint64_t lsass_eprocess, uint32_t peb_offset,
    const LsaKeys& keys);
