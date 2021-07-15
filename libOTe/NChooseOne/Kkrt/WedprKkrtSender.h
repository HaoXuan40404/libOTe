#pragma once
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
// #include <cryptoTools/Crypto/RandomOracle.h>
#if defined(ENABLE_SIMPLESTOT)
#include <cryptoTools/Crypto/Curve.h>
#endif

namespace osuCrypto
{
class WedprKkrtSender
{
public:
    u64 choiceCount;
    u64 msgCount;
    KkrtNcoOtSender kkrtNcoOtSender;
    DefaultBaseOT base;
    PRNG prng;
    BitVector bv;
    std::vector<block> msgsBase;
    bool maliciousSecure = false;
    u64 countBase;
    u64 statSecParam = 40;
    u64 inputBitCount = 128;
#if defined(ENABLE_SIMPLESTOT)
    EllipticCurve curve;
    // EccNumber a;
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    RECEIVER recver;
#endif
    Matrix<block> messages;  // OT message
    std::vector<u64> keys;   // index

    // for aes
    std::vector<std::vector<u8>> hash;            // OT message Hash
    std::vector<std::vector<block>> dataMessage;  // maybe useless
    std::vector<std::vector<block>> enMessage;

    // block seed;


    // WedprKkrtSender() = default;
    // WedprKkrtSender(const WedprKkrtSender&) = delete;
    // should use k-v map ids-messages
    WedprKkrtSender(u64 _choiceCount, u64 _msgCount, const Matrix<block>& _messages,
        const std::vector<u64>& _keys)
    {
        choiceCount = _choiceCount;
        msgCount = _msgCount;
        messages = _messages;
        keys = _keys;
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
// #if defined(ENABLE_SIMPLESTOT)
//         EccNumber _a(curve, prng);
//         a = _a;
// #endif
    };

    WedprKkrtSender(u64 _choiceCount, u64 _msgCount,
        const std::vector<std::vector<block>>& _dataMessage, const std::vector<u64>& _keys)
    {
        choiceCount = _choiceCount;
        msgCount = _msgCount;
        keys = _keys;
        // prng(sysRandomSeed());
        messages.resize(_choiceCount, _msgCount);
        PRNG _prng(sysRandomSeed());
        prng.SetSeed(_prng.getSeed());
        kkrtNcoOtSender.configure(maliciousSecure, statSecParam, inputBitCount);
        countBase = kkrtNcoOtSender.getBaseOTCount();
        msgsBase.resize(countBase);
        bv.resize(countBase);
        bv.randomize(prng);

        // generate AES random key
        // enc data block
        // cpmute key hash
        // need dataMessageToDecBlock
        enMessage.resize(_msgCount);
        hash.resize(_msgCount);
        dataMessage = _dataMessage;
    };

    ~WedprKkrtSender() {}

    // WedprKkrtSender* addressOfObject(void) {
    //     return this;
    // }

    void dataMessageToDecBlock();
#if defined(ENABLE_SIMPLESTOT)
    void step2ExtendSeedPack(block& baseOtSeed, std::vector<u8>& SPack, std::vector<u8>& RSPackResult);
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    void step2ExtendSeedPack(const u8* sPackBuffer, u8* rSPackResult);
#endif
    void step4GenerateSeed(block& seed, u8* comm);
    void step6SetMatrix(const block& theirSeed, const Matrix<block>& mT, const block& mySeed,
        Matrix<block>& sendMatrix);
    // void step6SetMatrixWithDecMessage(const block& theirSeed,  const Matrix<block>& mT, const
    // block& mySeed, Matrix<block>& sendMatrix, std::vector<std::vector<block>> enMessage,
    // std::vector<u8[RandomOracle::HashSize]> hash);
};
}  // namespace osuCrypto

// #ifdef ENABLE_KKRT


// #endif