#include "memory.h"
#include <algorithm>

// ----------------------------------------------------------------
// Page table walk: PML4 -> PDPT -> PD -> PT
// Supports large pages (1GB, 2MB) and transition pages
// ----------------------------------------------------------------
std::optional<uint64_t> vtp(HANDLE h, uint64_t dtb, uint64_t va) {
    uint64_t table_base = dtb & PFN_MASK;

    struct Level {
        int      shift;
        uint64_t large_mask;
        bool     can_be_large;
    };

    constexpr Level levels[] = {
        { 39, 0,                  false },  // PML4
        { 30, 0xFFFFC0000000ULL,  true  },  // PDPT (1GB page)
        { 21, 0xFFFFFFFE00000ULL, true  },  // PD   (2MB page)
    };

    for (auto& lvl : levels) {
        size_t idx = (va >> lvl.shift) & 0x1FF;
        auto entry_data = phys_read(h, table_base + idx * 8, 8);
        if (entry_data.empty()) return std::nullopt;
        uint64_t entry = rp(entry_data.data(), 0);

        if (!(entry & 1)) return std::nullopt;

        if (lvl.can_be_large && (entry & 0x80)) {
            return (entry & lvl.large_mask) | (va & ((1ULL << lvl.shift) - 1));
        }

        table_base = entry & PFN_MASK;
    }

    // PT level
    size_t idx = (va >> 12) & 0x1FF;
    auto entry_data = phys_read(h, table_base + idx * 8, 8);
    if (entry_data.empty()) return std::nullopt;
    uint64_t entry = rp(entry_data.data(), 0);

    // Present
    if (entry & 1)
        return (entry & PFN_MASK) | (va & 0xFFF);

    // Transition page (standby list, bit 11 set)
    if (entry & 0x800) {
        constexpr uint64_t masks[] = { 0xFFFFFF000ULL, 0xFFFFFFF000ULL, 0xFFFFFFFF000ULL, PFN_MASK };
        for (auto mask : masks) {
            uint64_t pa = (entry & mask) | (va & 0xFFF);
            auto test = phys_read(h, pa & ~0xFFFULL, 16);
            if (!test.empty()) {
                bool all_zero = std::all_of(test.begin(), test.begin() + 16,
                                            [](uint8_t b) { return b == 0; });
                if (!all_zero) return pa;
            }
        }
        return (entry & 0xFFFFFF000ULL) | (va & 0xFFF);
    }

    return std::nullopt;
}

// ----------------------------------------------------------------
// Read from process virtual address space via physical translation
// ----------------------------------------------------------------
Bytes proc_read(HANDLE h, uint64_t dtb, uint64_t va, size_t size) {
    Bytes result;
    result.reserve(size);
    size_t off = 0;

    while (off < size) {
        uint64_t page_off = (va + off) & 0xFFF;
        size_t chunk = std::min<size_t>(size - off, 0x1000 - page_off);

        auto pa = vtp(h, dtb, va + off);
        if (!pa.has_value()) {
            result.insert(result.end(), chunk, 0);
        } else {
            auto data = phys_read(h, *pa, chunk);
            if (data.size() >= chunk) {
                result.insert(result.end(), data.begin(), data.begin() + chunk);
            } else {
                result.insert(result.end(), chunk, 0);
            }
        }
        off += chunk;
    }
    return result;
}

// ----------------------------------------------------------------
// Read a single pointer from process VA
// ----------------------------------------------------------------
uint64_t read_ptr(HANDLE h, uint64_t dtb, uint64_t va) {
    auto d = proc_read(h, dtb, va, 8);
    return d.size() >= 8 ? rp(d.data(), 0) : 0;
}

// ----------------------------------------------------------------
// Resolve RIP-relative 32-bit displacement
// ----------------------------------------------------------------
uint64_t resolve_rip(HANDLE h, uint64_t dtb, uint64_t va) {
    auto d = proc_read(h, dtb, va, 4);
    if (d.size() < 4) return 0;
    return va + 4 + ri(d.data(), 0);
}

// ----------------------------------------------------------------
// Read UNICODE_STRING { USHORT Length; USHORT MaxLength; PWSTR Buffer; }
// ----------------------------------------------------------------
std::wstring read_ustr(HANDLE h, uint64_t dtb, const uint8_t* data, size_t off) {
    uint16_t length = rw(data, off);
    uint64_t buf    = rp(data, off + 8);
    if (!length || !buf) return {};

    auto raw = proc_read(h, dtb, buf, length);
    if (raw.size() < length) return {};

    return std::wstring(
        reinterpret_cast<const wchar_t*>(raw.data()),
        length / sizeof(wchar_t)
    );
}

// ----------------------------------------------------------------
// Read ANSI_STRING { USHORT Length; USHORT MaxLength; PCHAR Buffer; }
// ----------------------------------------------------------------
std::string read_astr(HANDLE h, uint64_t dtb, const uint8_t* data, size_t off) {
    uint16_t length = rw(data, off);
    uint64_t buf    = rp(data, off + 8);
    if (!length || !buf) return {};

    auto raw = proc_read(h, dtb, buf, length);
    if (raw.size() < length) return {};

    return std::string(reinterpret_cast<const char*>(raw.data()), length);
}

// ----------------------------------------------------------------
// Pattern scan across process memory in 64KB chunks
// ----------------------------------------------------------------
std::vector<uint64_t> scan(HANDLE h, uint64_t dtb, uint64_t base, size_t size,
                           std::span<const uint8_t> pattern) {
    std::vector<uint64_t> results;
    constexpr size_t CHUNK = 0x10000;

    for (size_t off = 0; off < size; off += CHUNK) {
        size_t read_sz = std::min<size_t>(CHUNK, size - off);
        auto data = proc_read(h, dtb, base + off, read_sz);
        if (data.size() < pattern.size()) continue;

        for (size_t pos = 0; pos <= data.size() - pattern.size(); ++pos) {
            if (std::memcmp(data.data() + pos, pattern.data(), pattern.size()) == 0) {
                results.push_back(base + off + pos);
            }
        }
    }
    return results;
}
