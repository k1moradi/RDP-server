// SPDX-License-Identifier: GPL-3.0-or-later
#include "linux_logind_console_evidence.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <utility>

#ifdef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN
#include <systemd/sd-bus.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-login.h>

#include <cstdlib>
#include <cstring>
#include <memory>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace rdp_server::server::security
{
namespace
{

[[nodiscard]] bool validSessionId(std::string_view sessionId) noexcept
{
    if (sessionId.empty() || sessionId.size() > 64)
    {
        return false;
    }
    for (const char character : sessionId)
    {
        if ((character < 'a' || character > 'z') &&
            (character < 'A' || character > 'Z') &&
            (character < '0' || character > '9') &&
            character != '_' && character != '-')
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool validLocalDisplay(std::string_view display) noexcept
{
    if (display.size() < 2 || display.size() > 8 ||
        display.front() != ':' ||
        (display.size() > 2 && display[1] == '0'))
    {
        return false;
    }
    for (std::size_t index = 1; index < display.size(); ++index)
    {
        if (display[index] < '0' || display[index] > '9')
        {
            return false;
        }
    }
    return true;
}

#ifdef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN

using LibcString = std::unique_ptr<char, decltype(&std::free)>;

[[nodiscard]] bool readLogindString(
    int (*readField)(const char *, char **), const char *sessionId,
    LibcString &output) noexcept
{
    char *rawString = nullptr;
    const int status = readField(sessionId, &rawString);
    output.reset(rawString); // Free even if a failing provider populated it.
    return status >= 0 && rawString != nullptr;
}

[[nodiscard]] std::string_view boundedView(
    const LibcString &value, std::size_t maximumLength) noexcept
{
    if (!value)
    {
        return {};
    }
    // Never construct an unbounded string_view from provider-owned bytes.
    const std::size_t length = ::strnlen(value.get(), maximumLength + 1);
    if (length == 0 || length > maximumLength)
    {
        return {};
    }
    return {value.get(), length};
}

struct SdBusDeleter final
{
    void operator()(sd_bus *bus) const noexcept
    {
        if (bus != nullptr)
            ::sd_bus_unref(bus);
    }
};

struct SdBusMessageDeleter final
{
    void operator()(sd_bus_message *message) const noexcept
    {
        if (message != nullptr)
            ::sd_bus_message_unref(message);
    }
};

[[nodiscard]] ConsoleDesktopLockState readDesktopLockState(
    const char *sessionId) noexcept
{
    sd_bus *rawBus = nullptr;
    if (::sd_bus_default_system(&rawBus) < 0 || rawBus == nullptr)
    {
        if (rawBus != nullptr)
            ::sd_bus_unref(rawBus);
        return ConsoleDesktopLockState::Unknown;
    }
    const std::unique_ptr<sd_bus, SdBusDeleter> bus(rawBus);

    sd_bus_error getSessionError{};
    sd_bus_message *rawReply = nullptr;
    const int getSessionStatus = ::sd_bus_call_method(
        bus.get(), "org.freedesktop.login1", "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager", "GetSession",
        &getSessionError, &rawReply, "s", sessionId);
    const std::unique_ptr<sd_bus_message, SdBusMessageDeleter> reply(rawReply);
    ::sd_bus_error_free(&getSessionError);
    if (getSessionStatus < 0 || reply == nullptr)
        return ConsoleDesktopLockState::Unknown;

    const char *sessionPath = nullptr;
    if (::sd_bus_message_read(reply.get(), "o", &sessionPath) < 0 ||
        sessionPath == nullptr)
        return ConsoleDesktopLockState::Unknown;

    int locked = 0;
    sd_bus_error lockError{};
    const int lockStatus = ::sd_bus_get_property_trivial(
        bus.get(), "org.freedesktop.login1", sessionPath,
        "org.freedesktop.login1.Session", "LockedHint",
        &lockError, 'b', &locked);
    ::sd_bus_error_free(&lockError);
    if (lockStatus < 0)
        return ConsoleDesktopLockState::Unknown;
    return locked != 0
        ? ConsoleDesktopLockState::Locked
        : ConsoleDesktopLockState::Unlocked;
}

#endif

} // namespace

bool consistentLogindSessionFacts(
    const LogindSessionFacts &session,
    const LogindActiveSeatFacts &secondSeat) noexcept
{
    return validSessionId(session.sessionId) &&
           secondSeat.sessionId == session.sessionId &&
           session.seat == "seat0" &&
           session.sessionType == "x11" &&
           session.sessionClass == "user" &&
           validLocalDisplay(session.display) &&
           session.seatOwnerUid != 0 &&
           session.seatOwnerUid != std::numeric_limits<std::uint32_t>::max() &&
           session.sessionOwnerUid == session.seatOwnerUid &&
           secondSeat.ownerUid == session.seatOwnerUid &&
           session.sessionStartRealtimeMicroseconds != 0 &&
           session.graphicalSeat && session.active && !session.remote;
}

LinuxCurrentX11DesktopSelection selectCurrentPhysicalX11Desktop(
    ConsoleOsEvidenceSource &source) noexcept
{
    const ConsoleSessionObservation session = source.readActiveConsole();
    const std::optional<std::uint64_t> now =
        source.readMonotonicMilliseconds();
    if (session.status != ConsoleEvidenceReadStatus::Observed ||
        !session.active || !session.physical || session.remote ||
        session.lockState != ConsoleDesktopLockState::Unlocked ||
        session.seat != "seat0" || !validSessionId(session.sessionId) ||
        !validLocalDisplay(session.display) || session.ownerUid == 0U ||
        session.localProcessUid == 0U ||
        session.ownerUid != session.localProcessUid ||
        session.sessionGeneration == 0U || !now.has_value() ||
        session.observedAtMonotonicMilliseconds == 0U ||
        *now < session.observedAtMonotonicMilliseconds ||
        *now - session.observedAtMonotonicMilliseconds >
            kMaximumConsoleObservationAgeMilliseconds)
    {
        return {};
    }

    LinuxCurrentX11DesktopSelection selection;
    selection.status = LinuxCurrentX11DesktopStatus::Eligible;
    selection.sessionIdLength = session.sessionId.size();
    selection.displayLength = session.display.size();
    std::copy(session.sessionId.begin(), session.sessionId.end(),
              selection.sessionIdBytes.begin());
    std::copy(session.display.begin(), session.display.end(),
              selection.displayBytes.begin());
    selection.ownerUid = session.ownerUid;
    selection.sessionGeneration = session.sessionGeneration;
    return selection;
}

ConsoleAccountObservation LinuxLogindReadOnlyEvidenceSource::readUnixAccount(
    std::string_view account) noexcept
{
    return accountSource_.readUnixAccount(account);
}

std::optional<std::uint64_t>
LinuxLogindReadOnlyEvidenceSource::readMonotonicMilliseconds() noexcept
{
    return accountSource_.readMonotonicMilliseconds();
}

ConsoleSessionObservation
LinuxLogindReadOnlyEvidenceSource::readActiveConsole() noexcept
{
#ifndef XRDP_CONSOLE_HAVE_SYSTEMD_LOGIN
    // Optional libsystemd dependency absent: never invent a local seat.
    return {};
#else
    // A systemd service manager and graphical physical seat must exist.
    if (::sd_booted() <= 0 || ::sd_seat_can_graphical("seat0") <= 0)
    {
        return {};
    }

    char *initialSessionRaw = nullptr;
    uid_t initialSeatUid{};
    const int seatReadStatus =
        ::sd_seat_get_active("seat0", &initialSessionRaw, &initialSeatUid);
    LibcString initialSession{initialSessionRaw, &std::free};
    const std::string_view sessionId = boundedView(initialSession, 64);
    if (seatReadStatus < 0 || !validSessionId(sessionId) ||
        initialSeatUid == 0 ||
        !std::in_range<std::uint32_t>(initialSeatUid))
    {
        return {};
    }

    uid_t sessionUid{};
    std::uint64_t startedAtRealtimeMicroseconds{};
    LibcString seat{nullptr, &std::free};
    LibcString display{nullptr, &std::free};
    LibcString sessionType{nullptr, &std::free};
    LibcString sessionClass{nullptr, &std::free};
    if (::sd_session_get_uid(initialSession.get(), &sessionUid) < 0 ||
        ::sd_session_get_start_time(initialSession.get(),
                                    &startedAtRealtimeMicroseconds) < 0 ||
        !readLogindString(::sd_session_get_seat, initialSession.get(), seat) ||
        !readLogindString(::sd_session_get_display, initialSession.get(),
                          display) ||
        !readLogindString(::sd_session_get_type, initialSession.get(),
                          sessionType) ||
        !readLogindString(::sd_session_get_class, initialSession.get(),
                          sessionClass))
    {
        return {};
    }

    const int active = ::sd_session_is_active(initialSession.get());
    const int remote = ::sd_session_is_remote(initialSession.get());
    if (active < 0 || remote < 0 ||
        !std::in_range<std::uint32_t>(sessionUid))
    {
        return {};
    }

    const std::string_view observedSeat = boundedView(seat, 16);
    const std::string_view observedDisplay = boundedView(display, 8);
    const std::string_view observedType = boundedView(sessionType, 16);
    const std::string_view observedClass = boundedView(sessionClass, 32);
    if (observedSeat.empty() || observedDisplay.empty() ||
        observedType.empty() || observedClass.empty())
    {
        return {};
    }

    // Seat may change mid-query: repeat the foreground lookup and compare
    // identity and UID, not just an is-active flag. This does NOT stop a
    // later switch and must never be used as a session lease.
    char *secondSessionRaw = nullptr;
    uid_t secondSeatUid{};
    const int repeatStatus =
        ::sd_seat_get_active("seat0", &secondSessionRaw, &secondSeatUid);
    LibcString secondSession{secondSessionRaw, &std::free};
    const std::string_view secondSessionId = boundedView(secondSession, 64);
    if (repeatStatus < 0 ||
        !std::in_range<std::uint32_t>(secondSeatUid))
    {
        return {};
    }

    const LogindSessionFacts facts{
        sessionId, observedSeat, observedDisplay, observedType, observedClass,
        static_cast<std::uint32_t>(initialSeatUid),
        static_cast<std::uint32_t>(sessionUid),
        startedAtRealtimeMicroseconds, true, active == 1, remote != 0};
    // The active seat could change during account/session sampling. Repeat
    // the *same session's* UID and creation identity after the second seat
    // observation. Any missing or replaced native fact denies the candidate;
    // this does not itself authenticate the remote user or grant consent.
    uid_t repeatedSessionUid{};
    std::uint64_t repeatedSessionStartMicroseconds{};
    if (::sd_session_get_uid(initialSession.get(), &repeatedSessionUid) < 0 ||
        repeatedSessionUid != sessionUid ||
        ::sd_session_get_start_time(
            initialSession.get(), &repeatedSessionStartMicroseconds) < 0 ||
        repeatedSessionStartMicroseconds != startedAtRealtimeMicroseconds ||
        !consistentLogindSessionFacts(
            facts, {secondSessionId, static_cast<std::uint32_t>(secondSeatUid)}) ||
        ::sd_session_is_active(initialSession.get()) != 1 ||
        ::sd_session_is_remote(initialSession.get()) != 0)
    {
        return {};
    }

    const auto observedAt = readMonotonicMilliseconds();
    const uid_t processUid = ::geteuid();
    if (!observedAt.has_value() || *observedAt == 0 ||
        processUid == 0 || !std::in_range<std::uint32_t>(processUid))
    {
        return {};
    }

    // login1 LockedHint is the strongest currently supported GNOME/logind
    // lock evidence. D-Bus failure remains Unknown and therefore fail-closed.
    const ConsoleDesktopLockState lockState =
        readDesktopLockState(initialSession.get());

    // Own the returned views. No provider-allocated buffer escapes, and
    // every libsystemd string is released by LibcString on each path.
    std::copy(sessionId.begin(), sessionId.end(), sessionIdBytes_.begin());
    sessionIdBytes_[sessionId.size()] = '\0';
    std::copy(observedDisplay.begin(), observedDisplay.end(),
              displayBytes_.begin());
    displayBytes_[observedDisplay.size()] = '\0';

    return {ConsoleEvidenceReadStatus::Observed,
            {sessionIdBytes_.data(), sessionId.size()}, "seat0",
            {displayBytes_.data(), observedDisplay.size()},
            facts.sessionOwnerUid, facts.sessionStartRealtimeMicroseconds,
            *observedAt, true, true,
            static_cast<std::uint32_t>(processUid), lockState, false};
#endif
}

} // namespace rdp_server::server::security
