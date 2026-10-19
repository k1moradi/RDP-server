// SPDX-License-Identifier: GPL-3.0-or-later
#include "windows_rdp_conflict_probe.h"

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>

namespace rdp_server::windows
{
namespace
{

constexpr DWORD kMaximumTcpTableBytes = 4U * 1024U * 1024U;

class ServiceHandle final
{
public:
    explicit ServiceHandle(SC_HANDLE value) noexcept : value_(value) {}
    ~ServiceHandle()
    {
        if (value_ != nullptr)
            CloseServiceHandle(value_);
    }

    ServiceHandle(const ServiceHandle &) = delete;
    ServiceHandle &operator=(const ServiceHandle &) = delete;

    [[nodiscard]] SC_HANDLE get() const noexcept { return value_; }

private:
    SC_HANDLE value_{};
};

[[nodiscard]] bool observeTermService(bool &active) noexcept
{
    active = false;
    ServiceHandle manager{
        OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (manager.get() == nullptr)
        return false;

    ServiceHandle service{
        OpenServiceW(manager.get(), L"TermService", SERVICE_QUERY_STATUS)};
    if (service.get() == nullptr)
        return false;

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    if (QueryServiceStatusEx(
            service.get(), SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            static_cast<DWORD>(sizeof(status)), &bytesNeeded) == FALSE)
        return false;

    active = status.dwCurrentState != SERVICE_STOPPED;
    return true;
}

[[nodiscard]] constexpr std::uint16_t hostPort(
    const DWORD nativePort) noexcept
{
    const auto low = static_cast<std::uint16_t>(nativePort & 0xffffU);
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(low >> 8U) |
        static_cast<std::uint16_t>(low << 8U));
}

template <typename Table, typename Row>
[[nodiscard]] bool tableContainsPort(
    const std::byte *bytes, const DWORD byteCount,
    const std::uint16_t requestedPort, bool &occupied) noexcept
{
    occupied = false;
    constexpr std::size_t headerBytes = offsetof(Table, table);
    if (bytes == nullptr || byteCount < headerBytes)
        return false;

    const auto *table = reinterpret_cast<const Table *>(bytes);
    const std::size_t availableRows =
        (static_cast<std::size_t>(byteCount) - headerBytes) / sizeof(Row);
    if (static_cast<std::size_t>(table->dwNumEntries) > availableRows)
        return false;

    for (DWORD index = 0; index < table->dwNumEntries; ++index)
    {
        if (hostPort(table->table[index].dwLocalPort) == requestedPort)
        {
            occupied = true;
            break;
        }
    }
    return true;
}

[[nodiscard]] bool observeTcpFamily(
    const ULONG addressFamily, const std::uint16_t requestedPort,
    bool &occupied) noexcept
{
    occupied = false;
    DWORD bytesNeeded = 0;
    const DWORD sizing = GetExtendedTcpTable(
        nullptr, &bytesNeeded, FALSE, addressFamily,
        TCP_TABLE_OWNER_PID_LISTENER, 0);
    if (sizing != ERROR_INSUFFICIENT_BUFFER ||
        bytesNeeded == 0 || bytesNeeded > kMaximumTcpTableBytes)
        return false;

    for (unsigned attempt = 0; attempt < 2; ++attempt)
    {
        if (bytesNeeded == 0 || bytesNeeded > kMaximumTcpTableBytes)
            return false;
        std::unique_ptr<std::byte[]> bytes{
            new (std::nothrow) std::byte[bytesNeeded]};
        if (!bytes)
            return false;

        DWORD tableBytes = bytesNeeded;
        const DWORD result = GetExtendedTcpTable(
            bytes.get(), &tableBytes, FALSE, addressFamily,
            TCP_TABLE_OWNER_PID_LISTENER, 0);
        if (result == ERROR_INSUFFICIENT_BUFFER)
        {
            bytesNeeded = tableBytes;
            continue;
        }
        if (result != NO_ERROR)
            return false;

        if (addressFamily == AF_INET)
            return tableContainsPort<MIB_TCPTABLE_OWNER_PID,
                                     MIB_TCPROW_OWNER_PID>(
                bytes.get(), tableBytes, requestedPort, occupied);
        if (addressFamily == AF_INET6)
            return tableContainsPort<MIB_TCP6TABLE_OWNER_PID,
                                     MIB_TCP6ROW_OWNER_PID>(
                bytes.get(), tableBytes, requestedPort, occupied);
        return false;
    }
    return false;
}

[[nodiscard]] bool observeRequestedPort(
    const std::uint16_t requestedPort, bool &occupied) noexcept
{
    occupied = false;
    if (requestedPort == 0)
        return false;

    bool ipv4Occupied = false;
    if (!observeTcpFamily(AF_INET, requestedPort, ipv4Occupied))
        return false;
    if (ipv4Occupied)
    {
        occupied = true;
        return true;
    }

    bool ipv6Occupied = false;
    if (!observeTcpFamily(AF_INET6, requestedPort, ipv6Occupied))
        return false;
    occupied = ipv6Occupied;
    return true;
}

} // namespace

WindowsRdpConflictStatus WindowsRdpConflictProbe::probe(
    const std::uint16_t requestedPort) const noexcept
{
    WindowsRdpConflictObservation observation{};
    observation.termServiceObserved =
        observeTermService(observation.termServiceActive);
    if (!observation.termServiceObserved || observation.termServiceActive)
        return classifyWindowsRdpConflict(observation);

    observation.requestedPortObserved =
        observeRequestedPort(requestedPort, observation.requestedPortInUse);
    return classifyWindowsRdpConflict(observation);
}

} // namespace rdp_server::windows
