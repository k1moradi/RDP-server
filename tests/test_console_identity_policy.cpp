// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/console_identity_policy.h"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <string_view>

using namespace rdp_server::server::security;

namespace
{
void testCandidateMatching()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001U, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    assert(policy.matchCandidate(
               {"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                1001U, 1001U, kConsoleViewPermission}) ==
           ConsolePolicyMatch::CandidateOnly);
    assert(policy.matchCandidate(
               {"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                1001U, 1002U, kConsoleViewPermission}) ==
           ConsolePolicyMatch::Denied);
}

void testDelegatedAccountBinding()
{
    ConsoleIdentityPolicy policy;
    assert(policy.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                       1001U, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    const std::uint64_t generation = policy.generation();
    assert(generation != 0);

    const auto match = [&](std::string_view principal,
                           std::string_view account) {
        return policy.matchPrincipalAccountCandidate(
            principal, account, generation);
    };
    assert(match("alice@EXAMPLE.TEST", "alice") ==
           ConsolePolicyMatch::CandidateOnly);
    assert(match("alice@EXAMPLE.TEST", "bob") == ConsolePolicyMatch::Denied);
    assert(match("bob@EXAMPLE.TEST", "alice") == ConsolePolicyMatch::Denied);
    assert(match("Alice@EXAMPLE.TEST", "alice") == ConsolePolicyMatch::Denied);
    assert(match("alice@EXAMPLE.TEST", "Alice") == ConsolePolicyMatch::Denied);
    assert(match("alice@OTHER.TEST", "alice") == ConsolePolicyMatch::Denied);
    assert(match("missing@EXAMPLE.TEST", "missing") ==
           ConsolePolicyMatch::Denied);
    assert(match("TERMSRV/host@EXAMPLE.TEST", "alice") ==
           ConsolePolicyMatch::Denied);
    assert(match("alice@EXAMPLE.TEST", "root") == ConsolePolicyMatch::Denied);
    assert(policy.matchPrincipalAccountCandidate(
               "alice@EXAMPLE.TEST", "alice", 0) ==
           ConsolePolicyMatch::Denied);

    const std::size_t originalSize = policy.size();
    assert(match("alice@EXAMPLE.TEST", "mallory") ==
           ConsolePolicyMatch::Denied);
    assert(policy.size() == originalSize);

    assert(policy.add({"bob@EXAMPLE.TEST", "bob", "seat0", ":0",
                       1002U, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    assert(policy.matchPrincipalAccountCandidate(
               "alice@EXAMPLE.TEST", "alice", generation) ==
           ConsolePolicyMatch::Denied);

    ConsoleIdentityPolicy ambiguous;
    assert(ambiguous.add({"alice@EXAMPLE.TEST", "alice", "seat0", ":0",
                          1001U, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    assert(ambiguous.add({"alice@EXAMPLE.TEST", "other", "seat0", ":1",
                          1002U, kConsoleViewPermission}) ==
           ConsoleRuleError::None);
    const auto ambiguousGeneration = ambiguous.generation();
    assert(ambiguous.matchPrincipalAccountCandidate(
               "alice@EXAMPLE.TEST", "alice", ambiguousGeneration) ==
           ConsolePolicyMatch::Denied);
    assert(ambiguous.matchPrincipalAccountCandidate(
               "alice@EXAMPLE.TEST", "other", ambiguousGeneration) ==
           ConsolePolicyMatch::Denied);
}
}

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        testCandidateMatching();
        testDelegatedAccountBinding();
        return 0;
    }
    if (argc != 2 || argv[1] == nullptr)
        return 2;
    const std::string_view selected{argv[1]};
    if (selected == "console-policy-candidate-matching")
    {
        testCandidateMatching();
        return 0;
    }
    if (selected == "console-policy-delegated-account-binding")
    {
        testDelegatedAccountBinding();
        return 0;
    }
    return 2;
}
