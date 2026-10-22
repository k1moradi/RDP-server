// SPDX-License-Identifier: GPL-3.0-or-later
#include "server/security/windows_authenticated_identity.h"

#if defined(_WIN32)

#include <windows.h>
#include <sspi.h>

#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace rdp_server::server::security
{

class WindowsSspiAuthenticatedIdentityProofTestAccess final
{
public:
    [[nodiscard]] static WindowsSspiAuthenticatedIdentityBindResult
    bindCurrentProcessToken(
        WindowsSspiAuthenticatedIdentityProof &proof) noexcept
    {
        HANDLE token = nullptr;
        if (!::OpenProcessToken(
                ::GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            return WindowsSspiAuthenticatedIdentityBindResult::
                SecurityTokenUnavailable;
        }
        return proof.adoptOwnedToken(token);
    }
};

} // namespace rdp_server::server::security

namespace
{

[[nodiscard]] bool readCurrentProcessSid(
    std::array<std::byte,
        rdp_server::server::security::kMaximumWindowsNativeSidBytes> &sid,
    std::size_t &sidBytes) noexcept
{
    HANDLE token = nullptr;
    if (!::OpenProcessToken(
            ::GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    struct TokenCloser final
    {
        HANDLE token{};
        ~TokenCloser()
        {
            if (token != nullptr)
                (void)::CloseHandle(token);
        }
    } tokenCloser{token};

    alignas(TOKEN_USER)
        std::array<std::byte, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE>
            userBuffer{};
    DWORD returnedBytes = 0;
    if (!::GetTokenInformation(
            token, TokenUser, userBuffer.data(),
            static_cast<DWORD>(userBuffer.size()), &returnedBytes) ||
        returnedBytes < sizeof(TOKEN_USER) ||
        returnedBytes > userBuffer.size())
        return false;

    const auto *const user =
        reinterpret_cast<const TOKEN_USER *>(userBuffer.data());
    if (user->User.Sid == nullptr || !::IsValidSid(user->User.Sid))
        return false;

    const DWORD length = ::GetLengthSid(user->User.Sid);
    if (length == 0 || length > sid.size() ||
        !::CopySid(
            static_cast<DWORD>(sid.size()), sid.data(), user->User.Sid))
        return false;

    sidBytes = static_cast<std::size_t>(length);
    return true;
}

} // namespace

int main(int argumentCount, char **arguments)
{
    using namespace rdp_server::server::security;

    static_assert(
        !std::is_copy_constructible_v<
            WindowsSspiAuthenticatedIdentityProof>);
    static_assert(
        !std::is_move_constructible_v<
            WindowsSspiAuthenticatedIdentityProof>);

    assert(argumentCount == 2);
    const std::string_view testCase{arguments[1]};

    if (testCase == "sspi-context-denials")
    {
        WindowsSspiAuthenticatedIdentityProof proof;
        assert(proof.authenticationGeneration() == 0);
        assert(!proof.matchesAuthenticatedSid({}));

        CtxtHandle invalid{};
        SecInvalidateHandle(&invalid);
        assert(proof.bindAcceptedSecurityContext(invalid) ==
               WindowsSspiAuthenticatedIdentityBindResult::
                   InvalidSecurityContext);
        assert(proof.authenticationGeneration() == 0);
        return 0;
    }

    assert(testCase == "process-token-generation-lifecycle");

    std::array<std::byte, kMaximumWindowsNativeSidBytes> expectedSid{};
    std::size_t expectedSidBytes = 0;
    assert(readCurrentProcessSid(expectedSid, expectedSidBytes));
    assert(expectedSidBytes != 0);

    WindowsSspiAuthenticatedIdentityProof proof;
    assert(WindowsSspiAuthenticatedIdentityProofTestAccess::
               bindCurrentProcessToken(proof) ==
           WindowsSspiAuthenticatedIdentityBindResult::Bound);
    const std::uint64_t firstGeneration =
        proof.authenticationGeneration();
    assert(firstGeneration != 0);
    assert(proof.matchesAuthenticatedSid(
        {expectedSid.data(), expectedSidBytes}));

    auto wrongSid = expectedSid;
    wrongSid[0] ^= std::byte{0x01};
    assert(!proof.matchesAuthenticatedSid(
        {wrongSid.data(), expectedSidBytes}));

    proof.revoke();
    assert(proof.authenticationGeneration() == 0);
    assert(!proof.matchesAuthenticatedSid(
        {expectedSid.data(), expectedSidBytes}));

    assert(WindowsSspiAuthenticatedIdentityProofTestAccess::
               bindCurrentProcessToken(proof) ==
           WindowsSspiAuthenticatedIdentityBindResult::Bound);
    const std::uint64_t secondGeneration =
        proof.authenticationGeneration();
    assert(secondGeneration > firstGeneration);

    // A failed replacement invalidates the previous identity instead of
    // retaining a usable generation.
    CtxtHandle invalid{};
    SecInvalidateHandle(&invalid);
    assert(proof.bindAcceptedSecurityContext(invalid) ==
           WindowsSspiAuthenticatedIdentityBindResult::
               InvalidSecurityContext);
    assert(proof.authenticationGeneration() == 0);
    assert(!proof.matchesAuthenticatedSid(
        {expectedSid.data(), expectedSidBytes}));
    return 0;
}

#else
int main() { return 0; }
#endif
