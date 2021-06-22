#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all
// copyright. No restrictions are placed on its use.
#include "libOTe/config.h"
#include <cryptoTools/Common/Defines.h>
#ifdef ENABLE_AKN
#include "libOTe/TwoChooseOne/OTExtInterface.h"
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Network/Channel.h>


namespace osuCrypto
{
class AknOtReceiver : public TimerAdapter
{
public:
    AknOtReceiver();
    ~AknOtReceiver();

    void init(
        u64 totalOTCount, u64 numberOfOnes, double p, OtExtReceiver& ots, Channel& chl, PRNG& prng)
    {
        std::vector<Channel> chls{chl};

        init(totalOTCount, numberOfOnes, p, ots, chls, prng);
    }


    void init(u64 totalOTCount, u64 numberOfOnes, double p, OtExtReceiver& ots, span<Channel> chls,
        PRNG& prng);

    std::vector<u64> mOnes, mZeros;
    std::vector<block> mMessages;
    BitVector mChoices;
};

}  // namespace osuCrypto
#endif