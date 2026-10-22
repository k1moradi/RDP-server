// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/native_desktop_authorization.h"
#include "windows/windows_native_desktop_owner.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>

using namespace rdp_server::windows;
using namespace rdp_server::server::security;

namespace
{
[[nodiscard]] WindowsNativeSessionEvidence makeWindowsEvidence() noexcept
{
    WindowsNativeSessionEvidence evidence{};
    evidence.userSid[0] = std::byte{0x01};
    evidence.userSid[1] = std::byte{0x05};
    evidence.userSid[2] = std::byte{0x15};
    evidence.userSid[3] = std::byte{0x2a};
    evidence.userSidBytes = 4;
    evidence.sessionId = 42U;
    evidence.authenticationIdLow = 101U;
    evidence.authenticationIdHigh = 202;
    evidence.logonTime100Nanoseconds = 303;
    evidence.logonType = 2U;
    return evidence;
}
class DenyOnlyWindowsIdentity final : public WindowsAuthenticatedIdentityProof
{
public:
    [[nodiscard]] std::uint64_t authenticationGeneration() const noexcept override
    { return 1; }
    [[nodiscard]] bool matchesAuthenticatedSid(
        std::span<const std::byte>) const noexcept override
    { return false; }
};
class UnavailableWindowsEvidence final : public WindowsNativeSessionEvidenceSource
{
public:
    [[nodiscard]] WindowsNativeSessionEvidenceStatus readCurrent(
        WindowsNativeSessionEvidence &output) const noexcept override
    {
        ++reads;
        output = {};
        return WindowsNativeSessionEvidenceStatus::Unavailable;
    }
    mutable unsigned reads{};
};
class PositiveWindowsIdentity final : public WindowsAuthenticatedIdentityProof
{
public:
    PositiveWindowsIdentity()
    {
        const auto evidence = makeWindowsEvidence();
        std::copy_n(evidence.userSid.begin(), evidence.userSidBytes, sid.begin());
        sidBytes = evidence.userSidBytes;
    }
    [[nodiscard]] std::uint64_t authenticationGeneration() const noexcept override
    { return 11U; }
    [[nodiscard]] bool matchesAuthenticatedSid(
        std::span<const std::byte> candidate) const noexcept override
    {
        return candidate.size() == sidBytes &&
               std::equal(candidate.begin(), candidate.end(), sid.begin());
    }
    std::array<std::byte, kMaximumWindowsNativeSidBytes> sid{};
    std::size_t sidBytes{};
};
class FakeStandaloneAuthenticatedSession final
    : public NativeDesktopAuthenticatedSessionProof
{
public:
    [[nodiscard]] NativeDesktopAuthenticationKind authenticationKind()
        const noexcept override
    {
        return NativeDesktopAuthenticationKind::StandalonePassword;
    }

    [[nodiscard]] std::uint64_t authenticationGeneration()
        const noexcept override
    {
        return generation;
    }

    [[nodiscard]] bool revalidatesAuthenticatedSession()
        const noexcept override
    {
        return valid && generation != 0U;
    }

    // Deliberately keep the base deny-only Windows SID matcher. Standalone
    // authentication proves this RDP application's accepted session, not a
    // local Windows account identity.
    std::uint64_t generation{23U};
    bool valid{true};
};

class PositiveWindowsEvidence final : public WindowsNativeSessionEvidenceSource
{
public:
    [[nodiscard]] WindowsNativeSessionEvidenceStatus readCurrent(
        WindowsNativeSessionEvidence &output) const noexcept override
    {
        output = evidence;
        return WindowsNativeSessionEvidenceStatus::Observed;
    }
    WindowsNativeSessionEvidence evidence{makeWindowsEvidence()};
};
class OwnerEvidenceSource final : public ConsoleOsEvidenceSource
{
public:
    ConsoleSessionObservation session{
        ConsoleEvidenceReadStatus::Observed, "owner-session", "seat0", ":0",
        1000U, 7U, 1000U, true, true, 1000U,
        ConsoleDesktopLockState::Unlocked, false};
    std::optional<std::uint64_t> now{1000U};
    [[nodiscard]] ConsoleAccountObservation readUnixAccount(
        std::string_view) noexcept override { return {}; }
    [[nodiscard]] ConsoleSessionObservation readActiveConsole() noexcept override
    { return session; }
    [[nodiscard]] std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override { return now; }
};
class OwnerAuthorityFixture final
{
public:
    explicit OwnerAuthorityFixture(
        std::uint32_t permissions =
            kConsoleViewPermission | kConsoleInputPermission)
        : authority(evidence)
    {
        evidence.session.observedAtMonotonicMilliseconds = *evidence.now;
        const OwnerSharingIntent intent{permissions, 60'000U};
        assert(authority.requestConsent(intent) ==
               OwnerConsentRequestResult::Granted);
    }
    OwnerEvidenceSource evidence{};
    CurrentOwnerSharingAuthority authority;
};
[[nodiscard]] WindowsDesktopLayout singleDisplayLayout() noexcept
{
    constexpr std::array<PortableRectangle, 1> monitors{
        PortableRectangle{0, 0, 2, 2}};
    WindowsDesktopLayout layout{};
    assert(makeWindowsDesktopLayout(monitors, layout));
    return layout;
}
struct FakeSessionSource final
{
    static bool read(void *, std::uint32_t targetSessionId,
                     WindowsCaptureSessionObservation &observation) noexcept
    {
        observation = {targetSessionId, targetSessionId, true};
        return true;
    }
    [[nodiscard]] WindowsCaptureSessionReadCallbacks callbacks() noexcept
    { return {this, &read}; }
};
struct FakeDxgiBackend final
{
    std::byte factory{}, adapter{}, output{}, device{}, immediateContext{},
        output1{}, duplication{};
    unsigned releases{};
    static FakeDxgiBackend &self(void *context) noexcept
    { return *static_cast<FakeDxgiBackend *>(context); }
    static bool createFactory(void *context, void *&out) noexcept
    { auto &b=self(context); out=&b.factory; return true; }
    static WindowsDxgiEnumerationResult adapterAt(
        void *context, void *, std::uint32_t index, void *&out) noexcept
    {
        auto &b=self(context);
        if(index!=0) return WindowsDxgiEnumerationResult::end;
        out=&b.adapter; return WindowsDxgiEnumerationResult::item;
    }
    static WindowsDxgiEnumerationResult outputAt(
        void *context, void *, std::uint32_t index, void *&out) noexcept
    {
        auto &b=self(context);
        if(index!=0) return WindowsDxgiEnumerationResult::end;
        out=&b.output; return WindowsDxgiEnumerationResult::item;
    }
    static bool describeOutput(
        void *, void *, WindowsDxgiOutputDescription &description) noexcept
    { description={1234U,{0,0,2,2},true,true}; return true; }
    static bool createDevice(
        void *context, void *, void *&device, void *&immediateContext) noexcept
    { auto &b=self(context); device=&b.device; immediateContext=&b.immediateContext; return true; }
    static bool queryOutput1(void *context, void *, void *&output1) noexcept
    { auto &b=self(context); output1=&b.output1; return true; }
    static WindowsDxgiDuplicationResult duplicate(
        void *context, void *, void *, void *&duplication) noexcept
    { auto &b=self(context); duplication=&b.duplication; return WindowsDxgiDuplicationResult::ready; }
    static void release(void *context, WindowsDxgiNativeResource, void *resource) noexcept
    { assert(resource!=nullptr); ++self(context).releases; }
    [[nodiscard]] WindowsDxgiNativeCallbacks callbacks() noexcept
    {
        return {this,&createFactory,&adapterAt,&outputAt,&describeOutput,
                &createDevice,&queryOutput1,&duplicate,&release};
    }
};
struct FakeCaptureBackend final
{
    std::array<std::byte,16> pixels{};
    std::byte frameToken{}, mappingToken{};
    unsigned acquisitions{}, releases{}, maps{}, unmaps{};
    static FakeCaptureBackend &self(void *context) noexcept
    { return *static_cast<FakeCaptureBackend *>(context); }
    static WindowsDxgiAcquireResult acquire(
        void *context, std::uint32_t timeoutMilliseconds,
        void *&resource, WindowsDxgiFrameInfo &frameInfo) noexcept
    {
        auto &b=self(context); assert(timeoutMilliseconds==0); ++b.acquisitions;
        resource=&b.frameToken; frameInfo={}; return WindowsDxgiAcquireResult::acquired;
    }
    static WindowsDxgiReleaseResult release(void *context, void *resource) noexcept
    {
        auto &b=self(context); assert(resource==&b.frameToken); ++b.releases;
        return WindowsDxgiReleaseResult::released;
    }
    static WindowsD3D11MapResult stageAndMap(
        void *context, void *resource, WindowsD3D11MappedData &output) noexcept
    {
        auto &b=self(context); assert(resource==&b.frameToken); ++b.maps;
        output={b.pixels.data(),b.pixels.size(),{2,2},8,&b.mappingToken};
        return WindowsD3D11MapResult::mapped;
    }
    static void unmapAndRelease(void *context, void *mappingHandle) noexcept
    {
        auto &b=self(context); assert(mappingHandle==&b.mappingToken); ++b.unmaps;
    }
    [[nodiscard]] WindowsDxgiOwnedCaptureCallbacks callbacks() noexcept
    { return {{this,&acquire,&release},{this,&stageAndMap,&unmapAndRelease},{},{}}; }
};
struct FakeInputBackend final
{
    unsigned commands{};
    static std::size_t send(
        void *context, std::span<const WindowsNativeInputCommand> commands) noexcept
    {
        auto &b=*static_cast<FakeInputBackend *>(context);
        b.commands += static_cast<unsigned>(commands.size());
        return commands.size();
    }
    [[nodiscard]] WindowsInputCallbacks callbacks() noexcept
    { return {this,&send}; }
};
struct FakeCursorBackend final
{
    static WindowsCursorReadResult read(
        void *, WindowsNativeCursorObservation &observation) noexcept
    { observation={{0,0},1,1,0,0}; return WindowsCursorReadResult::ready; }
    [[nodiscard]] WindowsCursorReadCallbacks callbacks() noexcept
    { return {this,&read}; }
};
struct FrameSink final
{
    std::uint64_t expectedSession{};
    unsigned frames{};
    static bool consume(
        void *context, const FramebufferView &frame,
        WindowsCaptureGeneration generation) noexcept
    {
        auto &sink=*static_cast<FrameSink *>(context);
        assert(frame.valid() && frame.widthPixels==2 && frame.heightPixels==2);
        assert(frame.strideBytes==8 && frame.pixels.size()==16);
        assert(generation.session==sink.expectedSession && generation.device!=0);
        ++sink.frames; return true;
    }
    [[nodiscard]] WindowsR4BgraFrameConsumer consumer() noexcept
    { return {this,&consume}; }
};
} // namespace

void windowsNativeDesktopOwnerAuthorizationBoundaryDenials()
{
    using OpenSignature=WindowsNativeDesktopOpenResult (WindowsNativeDesktopOwner::*)(
        const WindowsNativeDesktopAuthorization &, std::uint64_t) noexcept;
    static_assert(std::is_same_v<decltype(&WindowsNativeDesktopOwner::open),OpenSignature>);
    static_assert(!std::is_constructible_v<WindowsNativeDesktopOwner,WindowsNativeSessionEvidence>);
    static_assert(!std::is_copy_constructible_v<WindowsNativeDesktopOwner>);
    static_assert(!std::is_move_constructible_v<WindowsNativeDesktopOwner>);
    static_assert(!kWindowsNativeDesktopPositiveActivationApproved);

    DenyOnlyWindowsIdentity identity;
    UnavailableWindowsEvidence evidence;
    CurrentOwnerSharingAuthority ownerSharingAuthority;
    WindowsNativeDesktopAuthorization authorization{identity,evidence,ownerSharingAuthority};
    WindowsNativeDesktopOwner owner;
    assert(owner.open(authorization,1)==WindowsNativeDesktopOpenResult::authorizationDenied);
    assert(evidence.reads==0);
    assert(owner.serviceOnce(authorization,1,{})==
           WindowsNativeDesktopServiceResult::authorizationRequired);
    assert(!owner.handleInput(authorization,1,WindowsKeyInput{0x1e,false,true}));
    WindowsCursorSnapshot cursor{};
    assert(owner.readCursorSnapshot(authorization,1,cursor)==WindowsCursorReadResult::failed);
    assert(owner.notifySessionChange(42)==WindowsCaptureSessionChangeResult::alreadyClosed);
    owner.retireAfterAuthorizationLoss();
    assert(owner.open(authorization,1)==WindowsNativeDesktopOpenResult::closed);
}

void windowsNativeDesktopOwnerAuthorizedOfflineLifecycle()
{
#if defined(_WIN32)
    OwnerAuthorityFixture ownerAuthority;
    PositiveWindowsIdentity identity;
    PositiveWindowsEvidence evidence;
    WindowsNativeDesktopAuthorization authorization{identity,evidence,ownerAuthority.authority};
    constexpr std::uint32_t permissions=kConsoleViewPermission|kConsoleInputPermission;
    assert(authorization.bindAuthenticatedIdentity(permissions)==
           NativeDesktopAuthorizationBindResult::Bound);
    const std::uint64_t generation=authorization.authorizationGeneration();

    FakeSessionSource session; FakeDxgiBackend dxgi; FakeCaptureBackend capture;
    FakeInputBackend input; FakeCursorBackend cursor;
    WindowsNativeDesktopTestConfiguration configuration{};
    configuration.layout=singleDisplayLayout();
    configuration.target={1234U,{0,0,2,2}};
    configuration.sessionReader=session.callbacks();
    configuration.dxgiCallbacks=dxgi.callbacks();
    configuration.captureCallbacks=capture.callbacks();
    configuration.cursorReader=cursor.callbacks();
    configuration.inputCallbacks=input.callbacks();

    WindowsNativeDesktopOwner desktop;
    assert(desktop.openForTesting(authorization,generation,configuration)==
           WindowsNativeDesktopOpenResult::ready);
    assert(desktop.ready());
    FrameSink sink{generation};
    assert(desktop.serviceOnce(authorization,generation,sink.consumer())==
           WindowsNativeDesktopServiceResult::frameConsumed);
    assert(sink.frames==1 && capture.acquisitions==1 && capture.maps==1 &&
           capture.unmaps==1 && capture.releases==1);
    WindowsCursorSnapshot snapshot{};
    assert(desktop.readCursorSnapshot(authorization,generation,snapshot)==
           WindowsCursorReadResult::ready);
    assert(snapshot.visible && (snapshot.position==WindowsDesktopPoint{0,0}));
    assert(desktop.handleInput(
        authorization,generation,WindowsKeyInput{0x1e,false,true}));
    assert(input.commands==1);
    ownerAuthority.authority.revoke(OwnerConsentRevocationReason::Stop);
    assert(desktop.serviceOnce(authorization,generation,sink.consumer())==
           WindowsNativeDesktopServiceResult::authorizationRequired);
    assert(!desktop.ready());
    assert(input.commands==1);
    assert(dxgi.releases!=0);
#else
    assert(false);
#endif
}

void windowsNativeDesktopOwnerAuthorizedViewOnlyOfflineLifecycle()
{
#if defined(_WIN32)
    OwnerAuthorityFixture ownerAuthority{kConsoleViewPermission};
    PositiveWindowsIdentity identity;
    PositiveWindowsEvidence evidence;
    WindowsNativeDesktopAuthorization authorization{
        identity, evidence, ownerAuthority.authority};
    assert(authorization.bindAuthenticatedIdentity(kConsoleViewPermission) ==
           NativeDesktopAuthorizationBindResult::Bound);
    const std::uint64_t generation =
        authorization.authorizationGeneration();
    assert(generation != 0);

    FakeSessionSource session;
    FakeDxgiBackend dxgi;
    FakeCaptureBackend capture;
    FakeCursorBackend cursor;
    WindowsNativeDesktopTestConfiguration configuration{};
    configuration.layout = singleDisplayLayout();
    configuration.target = {1234U, {0, 0, 2, 2}};
    configuration.sessionReader = session.callbacks();
    configuration.dxgiCallbacks = dxgi.callbacks();
    configuration.captureCallbacks = capture.callbacks();
    configuration.cursorReader = cursor.callbacks();

    WindowsNativeDesktopOwner desktop;
    assert(desktop.openForTesting(
               authorization, generation, configuration) ==
           WindowsNativeDesktopOpenResult::ready);
    assert(desktop.ready());

    FrameSink sink{generation};
    assert(desktop.serviceOnce(
               authorization, generation, sink.consumer()) ==
           WindowsNativeDesktopServiceResult::frameConsumed);
    assert(sink.frames == 1);

    WindowsCursorSnapshot snapshot{};
    assert(desktop.readCursorSnapshot(
               authorization, generation, snapshot) ==
           WindowsCursorReadResult::ready);

    ownerAuthority.authority.revoke(OwnerConsentRevocationReason::Stop);
    assert(desktop.serviceOnce(
               authorization, generation, sink.consumer()) ==
           WindowsNativeDesktopServiceResult::authorizationRequired);
    assert(!desktop.ready());
    assert(dxgi.releases != 0);
#else
    assert(false);
#endif
}

void windowsNativeDesktopOwnerStandaloneAuthenticatedSessionLifecycle()
{
#if defined(_WIN32)
    const auto makeConfiguration =
        [](FakeSessionSource &session,
           FakeDxgiBackend &dxgi,
           FakeCaptureBackend &capture,
           FakeCursorBackend &cursor,
           FakeInputBackend *input) noexcept
            -> WindowsNativeDesktopTestConfiguration {
        WindowsNativeDesktopTestConfiguration configuration{};
        configuration.layout = singleDisplayLayout();
        configuration.target = {1234U, {0, 0, 2, 2}};
        configuration.sessionReader = session.callbacks();
        configuration.dxgiCallbacks = dxgi.callbacks();
        configuration.captureCallbacks = capture.callbacks();
        configuration.cursorReader = cursor.callbacks();
        if (input != nullptr)
            configuration.inputCallbacks = input->callbacks();
        return configuration;
    };

    {
        OwnerAuthorityFixture ownerAuthority{kConsoleViewPermission};
        FakeStandaloneAuthenticatedSession authenticatedSession;
        PositiveWindowsEvidence evidence;
        WindowsNativeDesktopAuthorization authorization{
            authenticatedSession, evidence, ownerAuthority.authority};
        assert(authorization.bindAuthenticatedSession(kConsoleViewPermission) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const std::uint64_t generation =
            authorization.authorizationGeneration();
        assert(generation != 0U);

        FakeSessionSource session;
        FakeDxgiBackend dxgi;
        FakeCaptureBackend capture;
        FakeCursorBackend cursor;
        WindowsNativeDesktopOwner desktop;
        auto configuration =
            makeConfiguration(session, dxgi, capture, cursor, nullptr);
        assert(desktop.openForTesting(
                   authorization, generation, configuration) ==
               WindowsNativeDesktopOpenResult::ready);

        FrameSink sink{generation};
        assert(desktop.serviceOnce(
                   authorization, generation, sink.consumer()) ==
               WindowsNativeDesktopServiceResult::frameConsumed);
        assert(!desktop.handleInput(
            authorization, generation, WindowsKeyInput{0x1e, false, true}));
        // Requesting Input through a View-only grant is fail-closed. The
        // Windows owner retires rather than retaining a native lifetime that
        // was just asked to exceed its R2 permission scope.
        assert(!desktop.ready());
        assert(dxgi.releases != 0U);
    }

    {
        OwnerAuthorityFixture ownerAuthority;
        FakeStandaloneAuthenticatedSession authenticatedSession;
        PositiveWindowsEvidence evidence;
        WindowsNativeDesktopAuthorization authorization{
            authenticatedSession, evidence, ownerAuthority.authority};
        constexpr std::uint32_t permissions =
            kConsoleViewPermission | kConsoleInputPermission;
        assert(authorization.bindAuthenticatedSession(permissions) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const std::uint64_t generation =
            authorization.authorizationGeneration();

        FakeSessionSource session;
        FakeDxgiBackend dxgi;
        FakeCaptureBackend capture;
        FakeCursorBackend cursor;
        FakeInputBackend input;
        WindowsNativeDesktopOwner desktop;
        auto configuration =
            makeConfiguration(session, dxgi, capture, cursor, &input);
        assert(desktop.openForTesting(
                   authorization, generation, configuration) ==
               WindowsNativeDesktopOpenResult::ready);
        assert(desktop.handleInput(
            authorization, generation, WindowsKeyInput{0x1e, false, true}));
        assert(input.commands == 1U);

        // Replacing the exact accepted standalone session invalidates R2.
        // R6 must retire without posting synthetic native input afterward.
        ++authenticatedSession.generation;
        FrameSink sink{generation};
        assert(desktop.serviceOnce(
                   authorization, generation, sink.consumer()) ==
               WindowsNativeDesktopServiceResult::authorizationRequired);
        assert(!desktop.ready());
        assert(authorization.authorizationGeneration() == 0U);
        assert(input.commands == 1U);
        assert(dxgi.releases != 0U);
    }

    {
        OwnerAuthorityFixture ownerAuthority;
        FakeStandaloneAuthenticatedSession authenticatedSession;
        PositiveWindowsEvidence evidence;
        WindowsNativeDesktopAuthorization authorization{
            authenticatedSession, evidence, ownerAuthority.authority};
        constexpr std::uint32_t permissions =
            kConsoleViewPermission | kConsoleInputPermission;
        assert(authorization.bindAuthenticatedSession(permissions) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const std::uint64_t generation =
            authorization.authorizationGeneration();

        FakeSessionSource session;
        FakeDxgiBackend dxgi;
        FakeCaptureBackend capture;
        FakeCursorBackend cursor;
        FakeInputBackend input;
        WindowsNativeDesktopOwner desktop;
        auto configuration =
            makeConfiguration(session, dxgi, capture, cursor, &input);
        assert(desktop.openForTesting(
                   authorization, generation, configuration) ==
               WindowsNativeDesktopOpenResult::ready);

        ownerAuthority.authority.revoke(OwnerConsentRevocationReason::Stop);
        FrameSink sink{generation};
        assert(desktop.serviceOnce(
                   authorization, generation, sink.consumer()) ==
               WindowsNativeDesktopServiceResult::authorizationRequired);
        assert(!desktop.ready());
        assert(authorization.authorizationGeneration() == 0U);
        assert(dxgi.releases != 0U);
    }

    {
        OwnerAuthorityFixture ownerAuthority;
        FakeStandaloneAuthenticatedSession authenticatedSession;
        PositiveWindowsEvidence evidence;
        WindowsNativeDesktopAuthorization authorization{
            authenticatedSession, evidence, ownerAuthority.authority};
        constexpr std::uint32_t permissions =
            kConsoleViewPermission | kConsoleInputPermission;
        assert(authorization.bindAuthenticatedSession(permissions) ==
               NativeDesktopAuthorizationBindResult::Bound);
        const std::uint64_t generation =
            authorization.authorizationGeneration();

        FakeSessionSource session;
        FakeDxgiBackend dxgi;
        FakeCaptureBackend capture;
        FakeCursorBackend cursor;
        FakeInputBackend input;
        WindowsNativeDesktopOwner desktop;
        auto configuration =
            makeConfiguration(session, dxgi, capture, cursor, &input);
        assert(desktop.openForTesting(
                   authorization, generation, configuration) ==
               WindowsNativeDesktopOpenResult::ready);

        ++evidence.evidence.authenticationIdLow;
        FrameSink sink{generation};
        assert(desktop.serviceOnce(
                   authorization, generation, sink.consumer()) ==
               WindowsNativeDesktopServiceResult::authorizationRequired);
        assert(!desktop.ready());
        assert(authorization.authorizationGeneration() == 0U);
        assert(dxgi.releases != 0U);
    }
#else
    assert(false);
#endif
}

