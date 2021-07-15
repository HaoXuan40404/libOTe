#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all
// copyright. No restrictions are placed on its use.

//#if defined(__linux__) && not defined(NO_SIMPLEST_OT)
//#define ENABLE_SIMPLESTOT
//#endif

// #include "SimplestOT/ot_receiver.h"
// #include "SimplestOT/ot_sender.h"
#include "libOTe/config.h"
#include <cryptoTools/Crypto/Curve.h>


#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>

extern "C" {
#include "../SimplestOT/ot_receiver.h"
#include "../SimplestOT/ot_sender.h"
}

namespace osuCrypto
{
#if defined(ENABLE_SIMPLESTOT)
//#if defined(_MSC_VER)
//#    error "asm base simplest OT and windows is incompatible."
#if !(defined(ENABLE_RELIC) || defined(ENABLE_MIRACL))
#error "Non-asm base Simplest OT requires Relic or Miracl"
#endif

class SimplestOT : public OtReceiver, public OtSender
{
public:
    // set this to false if your use of the base OTs can tolerate
    // the receiver being able to choose the message that they receive.
    // If unsure leave as true as the strings will be uniform (safest but slower).
    bool mUniformOTs = true;

    void receive(
        const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl, u64 numThreads)
    {
        receive(choices, messages, prng, chl);
    }

    void send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl, u64 numThreads)
    {
        send(messages, prng, chl);
    }

    void receive(const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl) override;

    void send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl) override;

    // SIMPLEST_OT_PACK_BYTES = 32
    void sendSPack(EllipticCurve& curve,  EccNumber&a, PRNG& prng, std::vector<u8>& S_pack, block& seed);

    void receiveSPack(EllipticCurve& curve, const BitVector& choices, span<block> msg, PRNG& prng, const block& seed, std::vector<u8>& S_pack, std::vector<u8>& RS_pack_result);

    void sendMessage(EllipticCurve& curve, EccNumber&a, span<std::array<block, 2>> msg, block& seed, std::vector<u8>& RS_pack_result);
};

#endif

#if defined(ENABLE_SIMPLESTOT_ASM)
#if defined(_MSC_VER)
#error "asm base simplest OT and windows is incompatible."
#endif

class AsmSimplestOT : public OtReceiver, public OtSender
{
public:
    // set this to false if your use of the base OTs can tolerate
    // the receiver being able to choose the message that they receive.
    // If unsure leave as true as the strings will be uniform (safest but slower).
    bool mUniformOTs = true;

    void receive(
        const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl, u64 numThreads)
    {
        receive(choices, messages, prng, chl);
    }

    void send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl, u64 numThreads)
    {
        send(messages, prng, chl);
    }

    void receive(const BitVector& choices, span<block> messages, PRNG& prng, Channel& chl) override;

    void send(span<std::array<block, 2>> messages, PRNG& prng, Channel& chl) override;

    // SIMPLEST_OT_PACK_BYTES = 32
    void sendSPack(SENDER& sender, span<std::array<block, 2>> msg, PRNG& prng, u8 S_pack[SIMPLEST_OT_PACK_BYTES]);

    void receiveSPack(RECEIVER& receiver, const BitVector& choices, span<block> msg, PRNG& prng, const u8 S_pack[SIMPLEST_OT_PACK_BYTES], u8* RS_pack_result);

    void sendMessage(SENDER& sender, span<std::array<block, 2>> msg, const u8* RS_pack_result);
};

#endif
}  // namespace osuCrypto