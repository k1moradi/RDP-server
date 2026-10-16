// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "preauth_session.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <utility>

#include <openssl/ssl.h>

namespace rdp_server::server::transport
{

// One native recv/send or borrowed OpenSSL BIO callback may transfer at
// most one bounded 18 KiB chunk (TLS 1.2 ciphertext maximum payload;
// TLS 1.3 is smaller). Larger caller buffers are processed incrementally
// by their own event loop. No int narrowing on Windows and no allocation.
inline constexpr std::size_t kMaximumTcpIoChunkBytes = 18U * 1024U;

// Keep the post-handshake plaintext boundary no larger than one existing
// bounded TCP/BIO callback. Callers retain larger logical RDP PDUs and
// resubmit only the remaining stable suffix after explicit progress.
inline constexpr std::size_t kMaximumTlsApplicationIoBytes =
    kMaximumTcpIoChunkBytes;

// Immutable transport metadata captured by the SAME successful native
// accept call that creates the owned TCP connection. Address bytes stay
// in network order; port and IPv6 scope ID are host-order scalar values.
// This is not an authenticated user/principal or an OS admission grant.
enum class TcpPeerAddressFamily : std::uint8_t
{
    Unspecified,
    Ipv4,
    Ipv6,
};

struct TcpPeerEndpoint
{
    TcpPeerAddressFamily family{TcpPeerAddressFamily::Unspecified};
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port{};
    std::uint32_t ipv6ScopeId{};

    [[nodiscard]] constexpr bool valid() const noexcept
    {
        return family != TcpPeerAddressFamily::Unspecified;
    }

    friend constexpr bool operator==(
        const TcpPeerEndpoint &, const TcpPeerEndpoint &) noexcept = default;
};

// One result from a caller-owned NONBLOCKING TCP descriptor. A Progress
// result must have 1..buffer.size() bytes. Other outcomes must have zero.
// No invented timeouts, packet boundaries or automatic OS authorization.
enum class TcpIoOutcome : std::uint8_t
{
    Progress,
    WouldBlock,
    EndOfStream,
    Failure,
};

struct TcpIoResult
{
    TcpIoOutcome outcome{TcpIoOutcome::Failure};
    std::size_t bytes{};
};

// One synchronous post-handshake TLS application-data step. Progress is
// exact plaintext bytes consumed/produced. NeedRead/NeedWrite are derived
// from SSL_get_error and may oppose the nominal operation direction.
// Terminal outcomes close the sole SSL/BIO/socket owner.
enum class TlsApplicationIoOutcome : std::uint8_t
{
    Progress,
    NeedRead,
    NeedWrite,
    TlsClosed,
    TransportClosed,
    FatalTlsFailure,
    Invalid,
};

struct TlsApplicationIoResult
{
    TlsApplicationIoOutcome outcome{TlsApplicationIoOutcome::Invalid};
    std::size_t bytes{};
};

// Borrowed OS transport; the caller owns socket setup, readiness polling,
// closure/cancellation and lifetime. Must be called on one event loop.
class TcpNonblockingIo
{
public:
    virtual ~TcpNonblockingIo() = default;
    [[nodiscard]] virtual TcpIoResult receive(
        std::span<std::uint8_t> destination) noexcept = 0;
    [[nodiscard]] virtual TcpIoResult send(
        std::span<const std::uint8_t> source) noexcept = 0;
};

// Thin cross-platform native recv/send adapter. Borrowed socket is already
// connected and set NONBLOCKING by its owner. On Windows, WSAStartup must
// have been performed. On macOS/BSD, owner must prevent SIGPIPE (e.g.
// SO_NOSIGPIPE); Linux uses MSG_NOSIGNAL when available.
// No listening/binding/activation, no socket ownership or duplication.
class NativeTcpIo final : public TcpNonblockingIo
{
public:
    explicit NativeTcpIo(std::uintptr_t nativeSocket) noexcept
        : socket_(nativeSocket) {}
    [[nodiscard]] TcpIoResult receive(
        std::span<std::uint8_t> destination) noexcept override;
    [[nodiscard]] TcpIoResult send(
        std::span<const std::uint8_t> source) noexcept override;
private:
    std::uintptr_t socket_{};
};

struct TcpAcceptResult;

// The ONLY owner of an accepted native socket. The listener remains borrowed
// by acceptNonblockingTcpConnection; closing/moving this value never closes
// the listener or duplicates the accepted descriptor. Destroy SSL and its
// borrowed BIO, then PreauthTcpAdapter/NativeTcpIo, BEFORE closing this owner.
// Never move the owner while a callback is using its socket; all operations
// are confined to the same event-loop thread. WSAStartup/WSACleanup remain
// the platform runtime's responsibility on Windows.
class OwnedNativeTcpSocket final
{
public:
    static constexpr std::uintptr_t kInvalidSocket =
        (std::numeric_limits<std::uintptr_t>::max)();

    OwnedNativeTcpSocket() noexcept = default;
    OwnedNativeTcpSocket(const OwnedNativeTcpSocket &) = delete;
    OwnedNativeTcpSocket &operator=(const OwnedNativeTcpSocket &) = delete;
    OwnedNativeTcpSocket(OwnedNativeTcpSocket &&other) noexcept
        : socket_(std::exchange(other.socket_, kInvalidSocket)),
          peerEndpoint_(std::exchange(other.peerEndpoint_, TcpPeerEndpoint{})) {}
    OwnedNativeTcpSocket &operator=(OwnedNativeTcpSocket &&other) noexcept
    {
        if (this != &other)
        {
            close();
            socket_ = std::exchange(other.socket_, kInvalidSocket);
            peerEndpoint_ = std::exchange(other.peerEndpoint_, TcpPeerEndpoint{});
        }
        return *this;
    }
    ~OwnedNativeTcpSocket() { close(); }

    [[nodiscard]] bool valid() const noexcept
    {
        return socket_ != kInvalidSocket;
    }
    [[nodiscard]] std::uintptr_t nativeSocket() const noexcept
    {
        return socket_;
    }
    [[nodiscard]] TcpPeerEndpoint peerEndpoint() const noexcept
    {
        return valid() ? peerEndpoint_ : TcpPeerEndpoint{};
    }
    void close() noexcept;

private:
    explicit OwnedNativeTcpSocket(
        std::uintptr_t nativeSocket, TcpPeerEndpoint peerEndpoint) noexcept
        : socket_(nativeSocket), peerEndpoint_(peerEndpoint) {}
    friend TcpAcceptResult acceptNonblockingTcpConnection(
        std::uintptr_t listenerSocket) noexcept;

    std::uintptr_t socket_{kInvalidSocket};
    TcpPeerEndpoint peerEndpoint_{};
};

enum class TcpAcceptOutcome : std::uint8_t
{
    Accepted,
    WouldBlock,
    Failure,
};

struct TcpAcceptResult
{
    TcpAcceptOutcome outcome{TcpAcceptOutcome::Failure};
    OwnedNativeTcpSocket connection{};
};

// Accept ONE connection on a caller-owned, already-bound/listening,
// NONBLOCKING socket. Linux/Windows SO_ACCEPTCONN verifies listeners;
// Darwin uses supported SO_TYPE/peer-state and native accept errors.
// POSIX F_GETFL rejects blocking listeners BEFORE a native accept.
// Winsock callers MUST set FIONBIO (mode cannot be queried safely).
// No hidden wait/retry, bind policy, daemon or session admission. A successful result owns one NONBLOCKING, close-on-exec (POSIX)
// / non-inheritable (Windows) connected socket, suitable for NativeTcpIo.
// On macOS/BSD, configure SO_NOSIGPIPE before exposing the accepted socket.
[[nodiscard]] TcpAcceptResult acceptNonblockingTcpConnection(
    std::uintptr_t listenerSocket) noexcept;


 // One bounded batch of accepts on an already configured, caller-owned,
 // NONBLOCKING listener. An accepted descriptor is moved into the callback
 // (exactly once); the callback may adopt it in OwnedPreauthTcpConnection
 // or let RAII close it. No binding, listening, threads or OS admission.
 // The budget is an upper limit, not a claim that the backlog is empty.
 inline constexpr std::size_t kMaximumTcpAcceptBatch = 16;

 enum class TcpAcceptBatchOutcome : std::uint8_t
 {
     InvalidInput,
     WouldBlock,       // no accepted sockets and listener would block
     Drained,          // >=1 delivered, next native accept would block
     BudgetReached,    // exactly budget delivered; more MAY remain
     CallbackStopped,  // callback declined further accepts after transfer
     Failure,          // native accept/setup failed (possibly after progress)
 };

 struct TcpAcceptBatchResult
 {
     TcpAcceptBatchOutcome outcome{TcpAcceptBatchOutcome::InvalidInput};
     std::size_t accepted{};  // count transferred, even on later failure
 };

 using TcpAcceptedSocketCallback = bool (*)(
     OwnedNativeTcpSocket accepted, void *context) noexcept;

 // Exactly budget at most, bounded to 1..16; invalid inputs never
 // consume an incoming connection. Each one-shot accept checks its
 // listener role and POSIX nonblocking mode. No arrays/sleep/poll.
 // false from callback stops AFTER that descriptor transfers.
 [[nodiscard]] TcpAcceptBatchResult acceptNonblockingTcpBatch(
     std::uintptr_t listenerSocket, std::size_t budget,
     TcpAcceptedSocketCallback onAccepted, void *context) noexcept;

// Borrow an existing NONBLOCKING TCP transport for OpenSSL, using custom
// BIO callbacks rather than converting a Windows SOCKET to a POSIX int.
// SSL owns the BIO; the adapter/socket owner outlives every SSL operation.
// The SSL must have no BIO attached and its role must already be chosen.
// This is transport plumbing, NOT certificate/user authorization.
[[nodiscard]] bool attachNonblockingTcpBio(
    SSL *tls, TcpNonblockingIo &io) noexcept;

enum class TcpPreauthEvent : std::uint8_t
{
    NeedRead,
    NeedWrite,
    ReadyForTls,
    Closed,
    Invalid,
};

// One connection owner. An event loop calls onReadable/onWritable only when
// the borrowed socket is ready, until it returns ReadyForTls or Closed.
// Read sizes are the exact CR header/body remainder (<=260 bytes), so
// coalesced ClientHello bytes are left in the OS receive buffer for TLS.
// The successful X.224 Confirm must be completely sent before TLS starts.
// The failure response must be completely sent before terminal close.
// This adapter cannot authenticate, open an OS session or emit MCS replies.
class PreauthTcpAdapter final
{
public:
    explicit PreauthTcpAdapter(TcpNonblockingIo &io) noexcept : io_(io) {}

    [[nodiscard]] TcpPreauthEvent onReadable() noexcept;
    [[nodiscard]] TcpPreauthEvent onWritable() noexcept;
    // After ReadyForTls, the owner must attach the same configured SSL
    // to the connected nonblocking socket/BIO and drive the appropriate
    // readiness callback. No second state machine or listener is added.
    // Only after the complete X.224 Confirm: borrow the very same
    // connected TCP adapter for TLS network records. No socket ownership.
    [[nodiscard]] bool attachTlsTransport(SSL *serverTls) noexcept;

    // Direct parameterized handshake is retained for existing synthetic
    // BIO diagnostics. Once a network BIO has been attached, ONLY that
    // SSL/BIO pair can progress, including through this legacy API.
    [[nodiscard]] TlsHandshakeStatus onTlsIoReady(
        SSL *serverTls) noexcept;

    // Strict connected-TCP integration callbacks for the event loop.
    // SSL and its exact borrowed BIO are pinned by attachTlsTransport;
    // callers CANNOT substitute another TLS object at readiness time.
    // Requires all X.224 Confirm bytes to have been sent first.
    // The MCS callback consumes at most one encrypted, exact-length
    // packet via the SAME completed TLS and then closes this diagnostic.
    // These APIs NEVER allow authenticated MCS/channel/OS admission.
    [[nodiscard]] TlsHandshakeStatus onAttachedTlsIoReady() noexcept;
    [[nodiscard]] McsIntakeResult onAttachedMcsIoReady() noexcept;
    [[nodiscard]] PreauthConnectionStream &connection() noexcept
    {
        return connection_;
    }
    [[nodiscard]] const PreauthConnectionStream &connection() const noexcept
    {
        return connection_;
    }
    void close() noexcept
    {
        attachedServerTls_ = nullptr;
        attachedTcpBio_ = nullptr;
        connection_.close();
    }

private:
    [[nodiscard]] TcpPreauthEvent idleStatus() const noexcept;
    [[nodiscard]] bool matchesAttachedTlsTransport() const noexcept;
    [[nodiscard]] bool isEstablishedTlsTransport(
        const SSL *serverTls) const noexcept;

    // The enclosing nonmoving owner may verify that application I/O still
    // targets the exact SSL/BIO pair attached to this adapter. No mutable
    // SSL/BIO capability is exposed to R2/R3.
    friend class OwnedPreauthTcpConnection;

    TcpNonblockingIo &io_;
    PreauthConnectionStream connection_{};
    // Borrowed by this one connection owner, never another SSL/BIO owner.
    // Both must outlive this adapter and remain on its one event loop.
    SSL *attachedServerTls_{};
    BIO *attachedTcpBio_{};
};


 // Readiness desired by the one existing transport owner. No OS poller,
 // second phase controller or implicit timer is created here.
 // ConfigureTls means the full X.224 reply was sent; the event-loop
 // caller must supply an already configured server-role SSL before
 // scheduling network I/O for TLS.
 enum class TcpConnectionIoInterest : std::uint8_t
 {
     Read,
     Write,
     ConfigureTls,
     Closed,
 };


 // One bounded, readiness-driven OS poll of an already accepted TCP
 // connection. This is NOT a second session manager or server listener.
 enum class TcpConnectionPollOutcome : std::uint8_t
 {
     Dispatched,
     NoEvent,
     NeedsTls,
     Expired,
     Closed,
     Failure,
 };

 struct TcpConnectionPollResult
 {
     TcpConnectionPollOutcome outcome{TcpConnectionPollOutcome::Closed};
     TcpConnectionIoInterest nextInterest{TcpConnectionIoInterest::Closed};
 };

 // Absolute maximum wait for a single pollSocketOnce call. A long caller
 // timeout is split into bounded steps by the EXTERNAL runtime scheduler.
 inline constexpr std::chrono::milliseconds kMaximumTcpPollWait{25};


 // A single readiness wait on an EXTERNALLY configured nonblocking
 // listener followed by exactly ONE call to acceptNonblockingTcpBatch.
 // There is no listening socket owner, queue, service activation or
 // authenticated session in this helper. An expired deadline does NOT
 // steal a queued client or close the caller-owned listener.
 enum class TcpListenerPollOutcome : std::uint8_t
 {
     InvalidInput,
     NoEvent,
     Expired,
     BatchCompleted,
     Failure,
 };

 struct TcpListenerPollResult
 {
     TcpListenerPollOutcome outcome{TcpListenerPollOutcome::InvalidInput};
     // Meaningful only for BatchCompleted or Failure after readiness.
     TcpAcceptBatchResult batch{};
 };

 // Supply a monotonic deadline and one-step maxWait; clamped to 25ms.
 // POSIX: poll(POLLIN). Winsock: select(readfds) for listener
 // compatibility. Fail closed before polling a connected/non-listening
 // socket or a POSIX listener lacking O_NONBLOCK. Darwin uses SO_TYPE
 // and peer-state because it does not implement SO_ACCEPTCONN. No EINTR hidden retry.
 // An OS error does not close the listener. If ready, accept at most
 // budget connections and transfer each to the caller callback.
 [[nodiscard]] TcpListenerPollResult pollNonblockingTcpAcceptBatch(
     std::uintptr_t listenerSocket, std::size_t budget,
     TcpAcceptedSocketCallback onAccepted, void *context,
     std::chrono::steady_clock::time_point deadline,
     std::chrono::milliseconds maxWait = kMaximumTcpPollWait) noexcept;

 // R1: one event-loop-affine owner of an accepted socket, preauth and SSL.
 // Never move: the attached SSL/BIO borrows the embedded NativeTcpIo.
 // There is no additional protocol/session state machine or listener here.
 class OwnedPreauthTcpConnection final
 {
 public:
     using ServerTls = std::unique_ptr<SSL, decltype(&SSL_free)>;

     explicit OwnedPreauthTcpConnection(
         OwnedNativeTcpSocket acceptedSocket) noexcept;
     OwnedPreauthTcpConnection(const OwnedPreauthTcpConnection &) = delete;
     OwnedPreauthTcpConnection &operator=(const OwnedPreauthTcpConnection &) = delete;
     OwnedPreauthTcpConnection(OwnedPreauthTcpConnection &&) = delete;
     OwnedPreauthTcpConnection &operator=(OwnedPreauthTcpConnection &&) = delete;
     ~OwnedPreauthTcpConnection() { cancel(); }

     [[nodiscard]] bool active() const noexcept { return socket_.valid(); }
     [[nodiscard]] std::uintptr_t nativeSocket() const noexcept
     {
         return socket_.nativeSocket();
     }
     // Snapshot by value so R2/R3 never receives a mutable socket/address
     // capability. Invalid after cancellation/close; never authorization.
     [[nodiscard]] TcpPeerEndpoint peerEndpoint() const noexcept
     {
         return socket_.peerEndpoint();
     }
     [[nodiscard]] PreauthStage stage() const noexcept
     {
         return adapter_.connection().stage();
     }

     // Only for plaintext X.224 socket readiness. Subsequent TLS/MCS
     // readiness must be dispatched to the corresponding methods.
     [[nodiscard]] TcpPreauthEvent onReadable() noexcept;
     [[nodiscard]] TcpPreauthEvent onWritable() noexcept;
     // Takes unique SSL ownership even on error. Requires an already
     // configured server SSL and the entire X.224 Confirm sent first.
     [[nodiscard]] bool attachServerTls(ServerTls serverTls) noexcept;
     [[nodiscard]] TlsHandshakeStatus onTlsIoReady() noexcept;
     [[nodiscard]] McsIntakeResult onMcsIoReady() noexcept;

     // Bounded post-handshake encrypted byte-stream boundary for R2/R3.
     // Each call performs at most ONE SSL_read_ex/SSL_write_ex using the
     // exact owned SSL/BIO/socket and accepts 1..18 KiB only. No caller
     // span is retained. After WANT_READ/WANT_WRITE, retry the same logical
     // operation with the same byte count; write bytes must be unchanged
     // although the span address may move. Short progress is never retried
     // internally and authentication/session framing remains outside R1.
     [[nodiscard]] TlsApplicationIoResult readTlsApplicationData(
         std::span<std::uint8_t> destination) noexcept;
     [[nodiscard]] TlsApplicationIoResult writeTlsApplicationData(
         std::span<const std::uint8_t> source) noexcept;

     // Derived from the existing preauth phase and SSL/app WANT state, not a
     // second state machine. The caller polls for precisely this interest.
     [[nodiscard]] TcpConnectionIoInterest ioInterest() const noexcept;
     // Process at most ONE bounded existing preauth/TLS/MCS callback.
     // Application mode reports matching readiness only; it cannot retry
     // SSL I/O without the caller's current span. Wrong-direction, empty
     // or stale readiness never touches the socket.
     [[nodiscard]] TcpConnectionIoInterest onSocketReady(
         bool readable, bool writable) noexcept;
     // The caller owns its clock/timer and deadline policy. An expired
     // deadline closes SSL/BIO before the accepted socket; repeated
     // expiry has no effect. Time points must use steady_clock.
     [[nodiscard]] bool cancelIfExpired(
         std::chrono::steady_clock::time_point now,
         std::chrono::steady_clock::time_point deadline) noexcept;

     // One native poll/WSAPoll + at most ONE callback on this same owner.
     // Requires its event-loop thread. Does not bind/listen, retry hidden
     // EINTR, perform TLS configuration or infer authentication.
     // Both maxWait and deadline bound the wait to <= 25 milliseconds.
     // The caller retains the deadline policy and repeats this step.
     [[nodiscard]] TcpConnectionPollResult pollSocketOnce(
         std::chrono::steady_clock::time_point deadline,
         std::chrono::milliseconds maxWait = kMaximumTcpPollWait) noexcept;

     // Short-lived, read-only handoff for R2 certificate/peer inspection.
     // Non-null ONLY after actual TLS establishment; caller may not cache
     // this borrow across cancellation or advance SSL outside R1.
     // TLS establishment itself is NOT user identity or OS authorization.
     [[nodiscard]] const SSL *establishedTls() const noexcept;
     // Terminal, idempotent cancellation: free SSL/BIO before socket close.
     void cancel() noexcept;

 private:
     enum class TlsApplicationOperation : std::uint8_t
     {
         None,
         Read,
         Write,
     };

     [[nodiscard]] bool establishedApplicationTls() const noexcept;
     [[nodiscard]] TlsApplicationIoResult finishTlsApplicationStep(
         int sslResult, std::size_t bytes,
         TlsApplicationOperation operation,
         std::size_t attemptedBytes) noexcept;
     void clearPendingTlsApplicationIo() noexcept;

     OwnedNativeTcpSocket socket_{};
     NativeTcpIo io_;
     PreauthTcpAdapter adapter_;
     ServerTls serverTls_{nullptr, SSL_free};
     // Application mode begins only after the first valid bounded call.
     // This preserves the legacy first-MCS diagnostic until a real R2/R3
     // consumer opts into the byte-stream boundary.
     bool applicationIoActive_{};
     TlsApplicationOperation pendingApplicationOperation_{
         TlsApplicationOperation::None};
     TcpConnectionIoInterest pendingApplicationInterest_{
         TcpConnectionIoInterest::Read};
     // Size only: caller memory is never borrowed beyond a method call.
     std::size_t pendingApplicationBytes_{};
 };

} // namespace rdp_server::server::transport
