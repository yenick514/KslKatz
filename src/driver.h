#pragma once
#include "common.h"
#include <tuple>

constexpr DWORD KSLD_IOCTL = 0x222044;

#pragma pack(push, 1)
struct IoReadInput {
    uint32_t sub_cmd;
    uint32_t reserved;
    uint64_t address;
    uint64_t size;
    uint32_t mode;       // 1 = physical, 2 = virtual
    uint32_t padding;
};

struct IoSubCmd2 {
    uint32_t sub_cmd;
    uint32_t reserved;
};
#pragma pack(pop)

// RAII handle wrapper
class KslDHandle {
public:
    KslDHandle() = default;
    explicit KslDHandle(HANDLE h) : m_handle(h) {}
    ~KslDHandle() { close(); }
    KslDHandle(const KslDHandle&) = delete;
    KslDHandle& operator=(const KslDHandle&) = delete;
    KslDHandle(KslDHandle&& o) noexcept : m_handle(o.m_handle) { o.m_handle = INVALID_HANDLE_VALUE; }
    KslDHandle& operator=(KslDHandle&& o) noexcept {
        if (this != &o) { close(); m_handle = o.m_handle; o.m_handle = INVALID_HANDLE_VALUE; }
        return *this;
    }
    [[nodiscard]] HANDLE get() const { return m_handle; }
    [[nodiscard]] bool valid() const { return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr; }
    void close() { if (valid()) { CloseHandle(m_handle); m_handle = INVALID_HANDLE_VALUE; } }
private:
    HANDLE m_handle = INVALID_HANDLE_VALUE;
};

// Driver state
struct DriverState {
    KslDHandle   handle;
    std::wstring orig_image_path;
    std::wstring orig_allowed;
    bool         driver_was_deployed  = false;
    bool         service_was_created  = false;
};

DriverState setup_ksld();
void        cleanup_ksld(DriverState& state);

// Raw IOCTL
std::pair<bool, Bytes> ioctl_raw(HANDLE h, const void* in_buf, DWORD in_size, DWORD out_size = 4096);

// SubCmd 2 (register dump)
std::pair<bool, Bytes> subcmd2(HANDLE h);

// Physical / virtual reads
Bytes phys_read(HANDLE h, uint64_t addr, uint64_t size);
Bytes virt_read(HANDLE h, uint64_t addr, uint64_t size);
