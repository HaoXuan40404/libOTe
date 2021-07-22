#pragma once
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
// #include <cryptoTools/Crypto/RandomOracle.h>
#if defined(ENABLE_SIMPLESTOT)
#include <cryptoTools/Crypto/Curve.h>
#endif

namespace osuCrypto
{
class WedprKkrtReceiver
{
public:
    u64 choiceCount;
    u64 msgCount;
    KkrtNcoOtReceiver kkrtNcoOtReceiver;
    bool maliciousSecure = false;
    u64 countBase;
    u64 statSecParam = 40;
    u64 inputBitCount = 128;
    DefaultBaseOT base;
    PRNG prng;
    // BitVector bv;
    std::vector<std::array<block, 2>> msgsBase;
#if defined(ENABLE_SIMPLESTOT)
    EllipticCurve curve;
    block baseOtSeed;
    EccNumber randomNumber;
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    SENDER sender;
#endif
    std::vector<u64> keys;
    std::vector<block> recvMsgs;
    std::vector<block> recvMsgsResult;
    std::vector<std::vector<block>> dataMessage;  // decrept message


    // WedprKkrtReceiver() = default;
    // WedprKkrtReceiver(const WedprKkrtReceiver&) = delete;
    WedprKkrtReceiver(u64 _choiceCount, u64 _msgCount, const std::vector<u64>& chooses): randomNumber(curve)
    {
        choiceCount = _choiceCount;
        msgCount = _msgCount;
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
        recvMsgs.resize(choiceCount);
        recvMsgsResult.resize(choiceCount);
        EccNumber _randomNumber(curve, prng);
        randomNumber = _randomNumber;

    };


    ~WedprKkrtReceiver() {}

#if defined(ENABLE_SIMPLESTOT)
    void step1InitBaseOt(std::vector<u8>& SPack);
    void step3SetSeedPack(std::vector<u8>& RSPackResult);
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    void step1InitBaseOt(u8* SPack);
    void step3SetSeedPack(const u8* RSPackResult);
#endif
    void step5InitMatrix(const block& theirSeed, const u8* comm, block& MySeed, Matrix<block>& mT);
    void step7GetFinalResult(const Matrix<block>& sendMatrix);
    void step7GetFinalResultWithDecMessage(const Matrix<block>& sendMatrix,
        std::vector<std::vector<block>>& enMessage, std::vector<std::vector<u8>>& hash);
    void step7GetFinalResultWithChoice(
        const Matrix<block>& sendMatrix, const std::vector<block>& optChoice);
};
}  // namespace osuCrypto

// #ifdef ENABLE_KKRT


// #endif