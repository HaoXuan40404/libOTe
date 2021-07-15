#include "libOTe/NChooseOne/Kkrt/WedprKkrtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h>
#include <cryptoTools/Crypto/RandomOracle.h>

namespace osuCrypto
{
using namespace std;
void WedprKkrtSender::dataMessageToDecBlock()
{
    for (u64 i = 0; i < msgCount; i++)
    {
        // PRNG prngKey(sysRandomSeed());
        block seedKey = prng.get<block>();
        for (u64 j = 0; j < choiceCount; j++)
        {
            messages[j][i] = seedKey;
        }
        details::AES<details::AESTypes::NI> encKey(seedKey);
        std::vector<block> data;
        data = dataMessage[i];
        u64 length = data.size();
        std::vector<block> cipher(length);
        // enMessage[i].resize(length);
        for (u64 k = 0; k < length; k++)
        {
            encKey.ecbEncBlock(data[k], cipher[k]);
        }
        enMessage[i] = cipher;
        RandomOracle sha;
        sha.Update(seedKey);
        u8 cc[RandomOracle::HashSize];
        sha.Final(cc);
        std::vector<u8> temp(cc, cc + RandomOracle::HashSize);
        hash[i] = temp;
    }
}

#if defined(ENABLE_SIMPLESTOT)
    void WedprKkrtSender::step2ExtendSeedPack(block& baseOtSeed, std::vector<u8>& SPack, std::vector<u8>& RSPackResult) {
        base.receiveSPack(curve, bv, msgsBase, prng, baseOtSeed, SPack, RSPackResult);
        kkrtNcoOtSender.setBaseOts(msgsBase, bv);
    }
#endif

#ifdef ENABLE_SIMPLESTOT_ASM
void WedprKkrtSender::step2ExtendSeedPack(const u8* sPack, u8* rSPackResult)
{
    base.receiveSPack(recver, bv, msgsBase, prng, sPack, rSPackResult);
    kkrtNcoOtSender.setBaseOts(msgsBase, bv);
}
#endif

// seed maybe should use a pointer
void WedprKkrtSender::step4GenerateSeed(block& seed, u8* comm)
{
    seed = prng.get<block>();
    kkrtNcoOtSender.initStep1(choiceCount, seed, comm);
}

void WedprKkrtSender::step6SetMatrix(
    const block& theirSeed, const Matrix<block>& mT, const block& mySeed, Matrix<block>& sendMatrix)
{
    std::array<u64, 2> choice{0, 0};
    kkrtNcoOtSender.initStep2(mySeed, theirSeed);
    // std::cout<<"try copy mT"<<std::endl;
    // std::cout<<"mT.size()* sizeof(block) = "<<mT.size()* sizeof(block)<<std::endl;
    memcpy(kkrtNcoOtSender.mCorrectionVals.data(), mT.data(), mT.size() * sizeof(block));
    // std::cout<<"finish copy mT"<<std::endl;

    for (u64 i = 0; i < messages.rows(); ++i)
    {
        for (u64 j = 0; j < messages.cols(); ++j)
        {
            choice[0] = keys[j];
            // std::cout<<"sender choice = "<<choice[0]<<std::endl;
            kkrtNcoOtSender.encode(i, choice.data(), &sendMatrix(i, j));
            sendMatrix(i, j) = sendMatrix(i, j) ^ messages(i, j);
        }
    }
}

}  // namespace osuCrypto