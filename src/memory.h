#pragma once
#include "driver.h"

constexpr uint64_t PFN_MASK = 0xFFFFFFFFF000ULL;

// ----------------------------------------------------------------
// Virtual-to-physical translation (page table walk with transition page support)
// ----------------------------------------------------------------
std::optional<uint64_t> vtp(HANDLE h, uint64_t dtb, uint64_t va);

// ----------------------------------------------------------------
// Process virtual memory read via physical translation
// ----------------------------------------------------------------
Bytes proc_read(HANDLE h, uint64_t dtb, uint64_t va, size_t size);

// ----------------------------------------------------------------
// Convenience: read pointer from process VA
// ----------------------------------------------------------------
uint64_t read_ptr(HANDLE h, uint64_t dtb, uint64_t va);

// ----------------------------------------------------------------
// Resolve RIP-relative address (LEA / MOV with disp32)
// ----------------------------------------------------------------
uint64_t resolve_rip(HANDLE h, uint64_t dtb, uint64_t va);

// ----------------------------------------------------------------
// Read UNICODE_STRING from struct at offset
// ----------------------------------------------------------------
std::wstring read_ustr(HANDLE h, uint64_t dtb, const uint8_t* data, size_t off);

// ----------------------------------------------------------------
// Read ANSI_STRING from struct at offset
// ----------------------------------------------------------------
std::string read_astr(HANDLE h, uint64_t dtb, const uint8_t* data, size_t off);

// ----------------------------------------------------------------
// Pattern scan in process memory
// ----------------------------------------------------------------
std::vector<uint64_t> scan(HANDLE h, uint64_t dtb, uint64_t base, size_t size,
                           std::span<const uint8_t> pattern);
