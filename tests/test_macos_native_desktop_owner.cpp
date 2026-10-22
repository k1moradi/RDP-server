// SPDX-License-Identifier: GPL-3.0-or-later
#include "platform/macos/mac_native_desktop_owner.h"

#include <CoreVideo/CoreVideo.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>

namespace {

using namespace rdp::macos;
using namespace rdp_server::server::security;

static_assert(!std::is_constructible_v<MacNativeDesktopOwner,
                                        std::uint32_t, std::uint32_t>);
static_assert(!std::is_default_constructible_v<MacNativeDesktopOwner>);

class FakeOwnerEvidenceSource final : public ConsoleOsEvidenceSource {
public:
    ConsoleSessionObservation session{
        ConsoleEvidenceReadStatus::Observed,
        "owner-session",
        "seat0",
        ":0",
        1000U,
        7U,
        1000U,
        true,
        true,
        1000U,
        ConsoleDesktopLockState::Unlocked,
        false};
    std::optional<std::uint64_t> now{1000U};

    [[nodiscard]] ConsoleAccountObservation readUnixAccount(
        std::string_view) noexcept override {
        return {};
    }

    [[nodiscard]] ConsoleSessionObservation readActiveConsole() noexcept override {
        return session;
    }

    [[nodiscard]] std::optional<std::uint64_t>
    readMonotonicMilliseconds() noexcept override {
        return now;
    }
};

[[nodiscard]] MacNativeSessionEvidence makeMacEvidence() noexcept {
    MacNativeSessionEvidence evidence{};
    constexpr std::string_view consoleUser{"owner"};
    std::copy(consoleUser.begin(), consoleUser.end(), evidence.consoleUser.begin());
    evidence.consoleUserBytes = consoleUser.size();
    evidence.consoleUserId = 501U;
    evidence.auditUserId = 501U;
    evidence.auditSessionId = 77U;
    evidence.securitySessionId = 88U;
    evidence.securitySessionAttributes = 0x10U;
    return evidence;
}

class FakeMacEvidenceSource final : public MacNativeSessionEvidenceSource {
public:
    MacNativeSessionEvidenceStatus status{
        MacNativeSessionEvidenceStatus::Observed};
    MacNativeSessionEvidence evidence{makeMacEvidence()};

    [[nodiscard]] MacNativeSessionEvidenceStatus readCurrent(
        MacNativeSessionEvidence& output) const noexcept override {
        output = status == MacNativeSessionEvidenceStatus::Observed
            ? evidence : MacNativeSessionEvidence{};
        return status;
    }
};

class FakeMacAuthenticatedIdentity final : public MacAuthenticatedIdentityProof {
public:
    [[nodiscard]] std::uint64_t authenticationGeneration()
        const noexcept override {
        return generation;
    }

    [[nodiscard]] bool matchesAuthenticatedUserId(
        const std::uint32_t candidate) const noexcept override {
        return candidate == userId;
    }

    std::uint32_t userId{501U};
    std::uint64_t generation{12U};
};

class SecurityFixture final {
public:
    explicit SecurityFixture(
        const std::uint32_t permissions =
            kConsoleViewPermission | kConsoleInputPermission,
        const bool bind = true)
        : ownerAuthority(ownerEvidence),
          authorization(authenticatedIdentity, nativeEvidence, ownerAuthority) {
        ownerEvidence.session.observedAtMonotonicMilliseconds = *ownerEvidence.now;
        assert(ownerAuthority.requestConsent(
                   OwnerSharingIntent{permissions, 60'000U}) ==
               OwnerConsentRequestResult::Granted);
        if (bind) {
            assert(authorization.bindAuthenticatedIdentity(permissions) ==
                   NativeDesktopAuthorizationBindResult::Bound);
        }
    }

    FakeOwnerEvidenceSource ownerEvidence{};
    CurrentOwnerSharingAuthority ownerAuthority;
    FakeMacEvidenceSource nativeEvidence{};
    FakeMacAuthenticatedIdentity authenticatedIdentity{};
    MacNativeDesktopAuthorization authorization;
};

struct WatchFixture final {
    NativeDisplayReconfigurationWatch::ChangeRecorder displayRecorder{};
    NativeSessionChangeRecorder sessionRecorder{};
    std::uint64_t sessionEpoch{};
    std::size_t displayInstallCalls{};
    std::size_t displayRemoveCalls{};
    std::size_t sessionInstallCalls{};
    std::size_t sessionRemoveCalls{};

    static bool installDisplay(
        void* const context,
        const NativeDisplayReconfigurationWatch::ChangeRecorder recorder) noexcept {
        auto& self = *static_cast<WatchFixture*>(context);
        ++self.displayInstallCalls;
        self.displayRecorder = recorder;
        return recorder != nullptr;
    }

    static bool removeDisplay(void* const context) noexcept {
        auto& self = *static_cast<WatchFixture*>(context);
        ++self.displayRemoveCalls;
        self.displayRecorder = nullptr;
        return true;
    }

    static bool installSession(
        void* const context,
        const std::uint64_t registrationEpoch,
        const NativeSessionChangeRecorder recorder) noexcept {
        auto& self = *static_cast<WatchFixture*>(context);
        ++self.sessionInstallCalls;
        self.sessionEpoch = registrationEpoch;
        self.sessionRecorder = recorder;
        return registrationEpoch != 0 && recorder != nullptr;
    }

    static bool removeSession(void* const context) noexcept {
        auto& self = *static_cast<WatchFixture*>(context);
        ++self.sessionRemoveCalls;
        self.sessionEpoch = 0;
        self.sessionRecorder = nullptr;
        return true;
    }

    void recordDisplayChange() noexcept {
        assert(displayRecorder != nullptr);
        displayRecorder();
    }

    void recordSessionChange() noexcept {
        assert(sessionRecorder != nullptr && sessionEpoch != 0);
        sessionRecorder(sessionEpoch);
    }
};

struct DesktopFixture final {
    MacDesktopSessionObservation session{501U, 501U, true, true};
    ScreenCapturePreflightStatus capturePermission{
        ScreenCapturePreflightStatus::Granted};
    MacInputPermissionStatus inputPermission{MacInputPermissionStatus::Trusted};
    std::size_t sessionReads{};
    std::size_t captureReads{};
    std::size_t inputReads{};
    std::size_t nativeInputCommands{};
    std::array<MacNativeInputCommand, 8> lastInputCommands{};
    std::size_t lastInputCount{};

    static NativeDisplayReadStatus readDisplay(
        void*, std::span<NativeDisplayObservation> destination,
        std::size_t& reportedCount) noexcept {
        if (destination.empty()) {
            return NativeDisplayReadStatus::Unavailable;
        }
        destination[0] = {100U, 0.0, 0.0, 2.0, 2.0,
                          2U, 2U, 0U, 0.0};
        reportedCount = 1U;
        return NativeDisplayReadStatus::Ok;
    }

    static bool readSession(
        void* const context,
        MacDesktopSessionObservation& observation) noexcept {
        auto& self = *static_cast<DesktopFixture*>(context);
        ++self.sessionReads;
        observation = self.session;
        return true;
    }

    static ScreenCapturePreflightStatus readCapturePermission(
        void* const context) noexcept {
        auto& self = *static_cast<DesktopFixture*>(context);
        ++self.captureReads;
        return self.capturePermission;
    }

    static MacInputPermissionStatus readInputPermission(
        void* const context) noexcept {
        auto& self = *static_cast<DesktopFixture*>(context);
        ++self.inputReads;
        return self.inputPermission;
    }

    static std::size_t sendInput(
        void* const context,
        const std::span<const MacNativeInputCommand> commands) noexcept {
        auto& self = *static_cast<DesktopFixture*>(context);
        self.nativeInputCommands += commands.size();
        self.lastInputCount = commands.size();
        assert(commands.size() <= self.lastInputCommands.size());
        for (std::size_t index = 0; index < commands.size(); ++index) {
            self.lastInputCommands[index] = commands[index];
        }
        return commands.size();
    }
};

struct FakeCaptureBackendState final {
    std::shared_ptr<detail::MacScreenCaptureState> callbackState{};
    MacScreenCaptureBinding lastBinding{};
    std::size_t preflightCalls{};
    std::size_t prepareCalls{};
    std::size_t startCalls{};
    std::size_t stopCalls{};
    std::size_t closeCalls{};
};

class FakeCaptureBackend final : public detail::MacScreenCaptureBackend {
public:
    explicit FakeCaptureBackend(
        std::shared_ptr<FakeCaptureBackendState> state) noexcept
        : state_(std::move(state)) {}

    ScreenCapturePreflightStatus preflight() noexcept override {
        ++state_->preflightCalls;
        return ScreenCapturePreflightStatus::Granted;
    }

    std::expected<void, MacScreenCaptureError>
    prepare(const MacScreenCaptureBinding& binding,
            const std::shared_ptr<detail::MacScreenCaptureState>& state) noexcept override {
        ++state_->prepareCalls;
        state_->lastBinding = binding;
        state_->callbackState = state;
        state_->callbackState->prepared();
        return {};
    }

    std::expected<void, MacScreenCaptureError>
    start(const std::shared_ptr<detail::MacScreenCaptureState>& state) noexcept override {
        ++state_->startCalls;
        state_->callbackState = state;
        state_->callbackState->startCompleted(true);
        return {};
    }

    std::expected<void, MacScreenCaptureError>
    stop(const std::shared_ptr<detail::MacScreenCaptureState>& state) noexcept override {
        ++state_->stopCalls;
        state_->callbackState = state;
        state_->callbackState->stopCompleted(true);
        return {};
    }

    void close(
        const std::shared_ptr<detail::MacScreenCaptureState>& state) noexcept override {
        ++state_->closeCalls;
        state_->callbackState = state;
        state_->callbackState->close();
    }

private:
    std::shared_ptr<FakeCaptureBackendState> state_{};
};

struct PixelBufferOwner final {
    CVPixelBufferRef value{};
    PixelBufferOwner() = default;
    PixelBufferOwner(const PixelBufferOwner&) = delete;
    PixelBufferOwner& operator=(const PixelBufferOwner&) = delete;
    PixelBufferOwner(PixelBufferOwner&& other) noexcept : value(other.value) {
        other.value = nullptr;
    }
    PixelBufferOwner& operator=(PixelBufferOwner&& other) noexcept {
        if (this != &other) {
            if (value != nullptr) {
                CVPixelBufferRelease(value);
            }
            value = other.value;
            other.value = nullptr;
        }
        return *this;
    }
    ~PixelBufferOwner() {
        if (value != nullptr) {
            CVPixelBufferRelease(value);
        }
    }
};

[[nodiscard]] PixelBufferOwner makePixelBuffer(
    const std::span<std::byte> bytes,
    const std::size_t bytesPerRow) {
    PixelBufferOwner owner;
    const auto status = CVPixelBufferCreateWithBytes(
        kCFAllocatorDefault, 2U, 2U, kCVPixelFormatType_32BGRA,
        bytes.data(), bytesPerRow, nullptr, nullptr, nullptr, &owner.value);
    assert(status == kCVReturnSuccess && owner.value != nullptr);
    return owner;
}

struct BorrowFixture final {
    std::array<std::byte, 16> copied{};
    std::size_t calls{};
    std::uint64_t geometryGeneration{};
    std::uint64_t admittedSessionGeneration{};
    std::uint64_t frameSequence{};

    static bool consume(
        void* const context,
        const FramebufferView& frame,
        const std::uint64_t geometryGeneration,
        const std::uint64_t admittedSessionGeneration,
        const std::uint64_t frameSequence) noexcept {
        auto& self = *static_cast<BorrowFixture*>(context);
        assert(frame.valid());
        assert(frame.widthPixels == 2U && frame.heightPixels == 2U);
        assert(frame.strideBytes == 8U && frame.pixels.size() == 16U);
        ++self.calls;
        self.geometryGeneration = geometryGeneration;
        self.admittedSessionGeneration = admittedSessionGeneration;
        self.frameSequence = frameSequence;
        std::copy_n(frame.pixels.begin(), self.copied.size(), self.copied.begin());
        return true;
    }
};

struct OwnerFixture final {
    std::unique_ptr<SecurityFixture> security{};
    std::unique_ptr<WatchFixture> watch{};
    std::unique_ptr<DesktopFixture> desktop{};
    std::shared_ptr<FakeCaptureBackendState> captureState{};
    std::unique_ptr<MacNativeDesktopOwner> owner{};
    std::uint64_t authorizationGeneration{};
};

[[nodiscard]] MacNativeDesktopTestConfiguration makeConfiguration(
    OwnerFixture& fixture,
    const std::size_t maximumFramebufferBytes) {
    auto backend = std::make_unique<FakeCaptureBackend>(fixture.captureState);
    MacNativeDesktopTestConfiguration configuration{};
    configuration.selectedDisplayId = 100U;
    configuration.maximumFramebufferBytes = maximumFramebufferBytes;
    configuration.displayWatchCallbacks = {
        fixture.watch.get(),
        &WatchFixture::installDisplay,
        &WatchFixture::removeDisplay};
    configuration.sessionWatchCallbacks = {
        fixture.watch.get(),
        &WatchFixture::installSession,
        &WatchFixture::removeSession};
    configuration.displayReader = &DesktopFixture::readDisplay;
    configuration.sessionReader = {
        fixture.desktop.get(), &DesktopFixture::readSession};
    configuration.permissionReader = {
        fixture.desktop.get(),
        &DesktopFixture::readCapturePermission,
        &DesktopFixture::readInputPermission};
    configuration.inputCallbacks = {
        fixture.desktop.get(), &DesktopFixture::sendInput};
    configuration.captureBackend = std::move(backend);
    return configuration;
}

[[nodiscard]] std::expected<OwnerFixture, MacNativeDesktopOwnerError>
makeOwner(
    const std::uint32_t permissions =
        kConsoleViewPermission | kConsoleInputPermission,
    const bool bindAuthorization = true,
    const std::size_t maximumFramebufferBytes = 64U) {
    OwnerFixture fixture;
    fixture.security = std::make_unique<SecurityFixture>(
        permissions, bindAuthorization);
    fixture.watch = std::make_unique<WatchFixture>();
    fixture.desktop = std::make_unique<DesktopFixture>();
    fixture.captureState = std::make_shared<FakeCaptureBackendState>();
    fixture.authorizationGeneration =
        fixture.security->authorization.authorizationGeneration();

    auto owner = MacNativeDesktopOwner::createForTesting(
        fixture.security->authorization,
        fixture.authorizationGeneration,
        makeConfiguration(fixture, maximumFramebufferBytes));
    if (!owner) {
        return std::unexpected(owner.error());
    }
    fixture.owner = std::move(*owner);
    return std::move(fixture);
}

void advanceReady(OwnerFixture& fixture) {
    auto observation = fixture.owner->serviceOnce();
    assert(observation.state == MacNativeDesktopOwnerState::CapturePreparing);
    assert(fixture.captureState->preflightCalls == 1U);
    assert(fixture.captureState->prepareCalls == 1U);

    observation = fixture.owner->serviceOnce();
    assert(observation.state == MacNativeDesktopOwnerState::CaptureStarting);
    assert(fixture.captureState->startCalls == 1U);

    observation = fixture.owner->serviceOnce();
    assert(observation.state == MacNativeDesktopOwnerState::Ready);
    const PixelSize expectedPixelGeometry{2U, 2U};
    assert(observation.pixelGeometry == expectedPixelGeometry);
    assert(observation.geometryGeneration != 0U);
    assert(observation.admittedSessionGeneration ==
           fixture.authorizationGeneration);
}

void testFailClosedConstruction() {
    {
        auto denied = makeOwner(
            kConsoleViewPermission | kConsoleInputPermission, false);
        assert(!denied);
        assert(denied.error() ==
               MacNativeDesktopOwnerError::AuthorizationUnavailable);
    }
    {
        auto denied = makeOwner(
            kConsoleViewPermission | kConsoleInputPermission, true, 8U);
        assert(!denied);
        assert(denied.error() ==
               MacNativeDesktopOwnerError::FramebufferUnavailable);
    }
    {
        auto viewOnly = makeOwner(kConsoleViewPermission);
        assert(viewOnly);
        OwnerFixture fixture = std::move(*viewOnly);
        advanceReady(fixture);
        assert(!fixture.owner->serviceOnce().inputReady);
        const MacInputEvent keyDown = MacKeyInput{0x3BU, 0x1DU, false, true};
        assert(!fixture.owner->handleInput(keyDown));
        assert(fixture.owner->state() == MacNativeDesktopOwnerState::Ready);
        assert(fixture.desktop->nativeInputCommands == 0U);
    }
}

void testFrameInputAndAuthorizationRetirement() {
    auto created = makeOwner();
    assert(created);
    OwnerFixture fixture = std::move(*created);
    assert(fixture.watch->displayInstallCalls == 1U);
    assert(fixture.watch->sessionInstallCalls == 1U);
    advanceReady(fixture);
    assert(fixture.owner->serviceOnce().inputReady);

    alignas(64) std::array<std::byte, 24> source{};
    for (std::size_t index = 0; index < source.size(); ++index) {
        source[index] = static_cast<std::byte>(index + 1U);
    }
    auto pixelBuffer = makePixelBuffer(source, 12U);
    assert(fixture.captureState->callbackState != nullptr);
    assert(fixture.captureState->callbackState->consumeFrame(
               pixelBuffer.value,
               MacScreenCaptureFrameStatus::Complete) ==
           MacScreenCaptureFrameDisposition::Published);

    auto observation = fixture.owner->serviceOnce();
    assert(observation.state == MacNativeDesktopOwnerState::Ready);
    assert(observation.frameAvailable);
    assert(observation.latestFrameSequence == 1U);

    BorrowFixture borrowed;
    assert(fixture.owner->borrowFramebuffer(
        observation.latestFrameSequence,
        MacNativeDesktopFrameConsumer{&borrowed, &BorrowFixture::consume}));
    assert(borrowed.calls == 1U);
    assert(borrowed.admittedSessionGeneration ==
           fixture.authorizationGeneration);
    assert(borrowed.frameSequence == 1U);
    const std::array<std::byte, 16> expected{
        std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
        std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8},
        std::byte{13}, std::byte{14}, std::byte{15}, std::byte{16},
        std::byte{17}, std::byte{18}, std::byte{19}, std::byte{20}};
    assert(borrowed.copied == expected);
    assert(!fixture.owner->borrowFramebuffer(
        2U, MacNativeDesktopFrameConsumer{&borrowed, &BorrowFixture::consume}));
    assert(fixture.security->authorization.authorizationGeneration() ==
           fixture.authorizationGeneration);

    const MacInputEvent keyDown = MacKeyInput{0x3BU, 0x1DU, false, true};
    assert(fixture.owner->handleInput(keyDown));
    assert(fixture.desktop->nativeInputCommands == 1U);

    // R2 native-session replacement must fail the next visit. R5 then retires
    // held input without posting a synthetic release into the replacement.
    ++fixture.security->nativeEvidence.evidence.auditSessionId;
    observation = fixture.owner->serviceOnce();
    assert(observation.state == MacNativeDesktopOwnerState::Revoked);
    assert(fixture.security->authorization.authorizationGeneration() == 0U);
    assert(fixture.owner->admittedSessionGeneration() == 0U);
    assert(fixture.desktop->nativeInputCommands == 1U);
    assert(fixture.captureState->closeCalls == 1U);
    assert(fixture.watch->sessionRemoveCalls == 1U);
    assert(fixture.watch->displayRemoveCalls == 1U);
    fixture.owner->revoke();
    assert(fixture.captureState->closeCalls == 1U);
}

void testInputPermissionRetirement() {
    auto created = makeOwner();
    assert(created);
    OwnerFixture fixture = std::move(*created);
    advanceReady(fixture);
    assert(fixture.owner->serviceOnce().inputReady);

    // Hold one key so permission loss also proves authority-loss retirement
    // never posts a synthetic release into a desktop whose TCC state changed.
    const MacInputEvent keyDown = MacKeyInput{0x3BU, 0x1DU, false, true};
    assert(fixture.owner->handleInput(keyDown));
    assert(fixture.desktop->nativeInputCommands == 1U);

    fixture.desktop->inputPermission = MacInputPermissionStatus::NotTrusted;
    const auto observation = fixture.owner->serviceOnce();
    assert(observation.state == MacNativeDesktopOwnerState::Revoked);
    assert(!observation.inputReady);
    assert(fixture.desktop->nativeInputCommands == 1U);
    assert(fixture.captureState->closeCalls == 1U);
    assert(fixture.watch->sessionRemoveCalls == 1U);
    assert(fixture.watch->displayRemoveCalls == 1U);
}

void testDisplayAndSessionRetirement() {
    {
        auto created = makeOwner();
        assert(created);
        OwnerFixture fixture = std::move(*created);
        advanceReady(fixture);
        fixture.watch->recordDisplayChange();
        const auto observation = fixture.owner->serviceOnce();
        assert(observation.state == MacNativeDesktopOwnerState::Revoked);
        assert(fixture.captureState->closeCalls == 1U);
    }
    {
        auto created = makeOwner();
        assert(created);
        OwnerFixture fixture = std::move(*created);
        advanceReady(fixture);
        fixture.watch->recordSessionChange();
        const auto observation = fixture.owner->serviceOnce();
        assert(observation.state == MacNativeDesktopOwnerState::Revoked);
        assert(fixture.captureState->closeCalls == 1U);
    }
}

} // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::string_view selected{argv[1]};
    if (selected == "fail-closed-construction") {
        testFailClosedConstruction();
    } else if (selected == "frame-input-lifecycle") {
        testFrameInputAndAuthorizationRetirement();
    } else if (selected == "input-permission-retirement") {
        testInputPermissionRetirement();
    } else if (selected == "display-session-retirement") {
        testDisplayAndSessionRetirement();
    } else {
        assert(false && "unknown test case");
    }
    return 0;
}
