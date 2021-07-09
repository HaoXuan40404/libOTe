#pragma once
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"


namespace osuCrypto
{
class WedprKkrtReceiver {
public:
    u64 numOTs;
    u64 numChosenMsgs;
    KkrtNcoOtReceiver kkrtNcoOtReceiver;
    bool maliciousSecure = false;
    u64 countBase;
    u64 statSecParam = 40;
    u64 inputBitCount = 128;
    DefaultBaseOT base;
    PRNG prng;
    // BitVector bv;
    std::vector<std::array<block, 2>> msgsBase;
    SENDER sender;
    std::vector<u64> keys;
    std::vector<block> recvMsgs;
    std::vector<block> recvMsgsResult;



    // WedprKkrtReceiver() = default;
    // WedprKkrtReceiver(const WedprKkrtReceiver&) = delete;
    WedprKkrtReceiver(u64 chooseCount, u64 msgsCount, const std::vector<u64>& chooses) {
        numOTs = chooseCount;
        numChosenMsgs = msgsCount;
        keys = chooses;
        // for(int i = 0; i < chooseCount; i++) {
        //     std::cout << "init keys[i] = " << keys[i] << std::endl;

        // }
        PRNG _prng(sysRandomSeed());
        prng.SetSeed(_prng.getSeed());
        // prng(sysRandomSeed());
        kkrtNcoOtReceiver.configure(maliciousSecure, statSecParam, inputBitCount);
        countBase = kkrtNcoOtReceiver.getBaseOTCount();
        msgsBase.resize(countBase);
        recvMsgs.resize(numOTs);
        recvMsgsResult.resize(numOTs);
    };


    ~WedprKkrtReceiver(){}

    void step1(u8* SPack);
    void step2(const u8* RSPackResult);
    void step3(const block& theirSeed, const u8* comm, block& MySeed, Matrix<block>& mT);
    void step4(const Matrix<block>& sendMatrix);
};
}

// #ifdef ENABLE_KKRT


// #endif