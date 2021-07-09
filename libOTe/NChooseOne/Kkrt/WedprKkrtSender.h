#pragma once
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"


namespace osuCrypto
{
class WedprKkrtSender {
public:
    u64 numOTs;
    u64 numChosenMsgs;
    KkrtNcoOtSender kkrtNcoOtSender;
    DefaultBaseOT base;
    PRNG prng;
    BitVector bv;
    std::vector<block> msgsBase;
    bool maliciousSecure = false;
    u64 countBase;
    u64 statSecParam = 40;
    u64 inputBitCount = 128;
    RECEIVER recver;
    Matrix<block> sendMessages;
    std::vector<u64> keys;

    // block seed;


    // WedprKkrtSender() = default;
    // WedprKkrtSender(const WedprKkrtSender&) = delete;
    // should use k-v map ids-messages
    WedprKkrtSender(u64 chooseCount, u64 msgsCount, const Matrix<block>& messages, const std::vector<u64>& ids) {
        numOTs = chooseCount;
        numChosenMsgs = msgsCount;
        sendMessages = messages;
        keys = ids;
        // for(int i = 0; i < msgsCount; i++) {
        //     std::cout << "WedprKkrtSender init keys[i] = " << keys[i] << std::endl;

        // }
        // prng(sysRandomSeed());
        PRNG _prng(sysRandomSeed());
        prng.SetSeed(_prng.getSeed());
        kkrtNcoOtSender.configure(maliciousSecure, statSecParam, inputBitCount);
        countBase = kkrtNcoOtSender.getBaseOTCount();
        msgsBase.resize(countBase);
        bv.resize(countBase);
        bv.randomize(prng);
    };

    ~WedprKkrtSender(){}

    void step1(const u8* SPack, u8* RSPackResult);
    void step2(block& seed, u8* comm);
    void step3(const block& mySeed, const block& theirSeed,  const Matrix<block>& mT, Matrix<block>& sendMatrix);
};
}

// #ifdef ENABLE_KKRT


// #endif