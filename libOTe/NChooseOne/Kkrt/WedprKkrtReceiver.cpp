#include "libOTe/NChooseOne/Kkrt/WedprKkrtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <iostream>
#include <ostream>

namespace osuCrypto
{
using namespace std;
#if defined(ENABLE_SIMPLESTOT)
void WedprKkrtReceiver::step1InitBaseOt(std::vector<u8>& SPack)
{
    base.sendSPack(curve, randomNumber, prng, SPack, baseOtSeed);
}

void WedprKkrtReceiver::step3SetSeedPack(std::vector<u8>& RSPackResult)
{
    base.sendMessage(curve, randomNumber, msgsBase, baseOtSeed, RSPackResult);
    kkrtNcoOtReceiver.setBaseOts(msgsBase);
}
#endif

#ifdef ENABLE_SIMPLESTOT_ASM
void WedprKkrtReceiver::step1InitBaseOt(u8* SPack)
{
    base.sendSPack(sender, msgsBase, prng, SPack);
}

void WedprKkrtReceiver::step3SetSeedPack(const u8* RSPackResult)
{
    base.sendMessage(sender, msgsBase, RSPackResult);
    kkrtNcoOtReceiver.setBaseOts(msgsBase);
}
#endif

void WedprKkrtReceiver::step5InitMatrix(
    const block& theirSeed, const u8* comm, block& MySeed, Matrix<block>& mT)
{
    MySeed = prng.get<block>();
    kkrtNcoOtReceiver.initStep1(choiceCount, MySeed, comm, theirSeed);
    std::array<u64, 2> choice{0, 0};
    for (u64 i = 0; i < recvMsgs.size(); ++i)
    {
        // recver.mCorrectionIdx
        choice[0] = keys[i];
        kkrtNcoOtReceiver.encode(i, choice.data(), &recvMsgs[i]);
    }
    // rows = choiceNum
    // cols = 4
    mT.resize(kkrtNcoOtReceiver.mT1.rows(), kkrtNcoOtReceiver.mT1.cols());
    memcpy(mT.data(), kkrtNcoOtReceiver.mT1.data(), kkrtNcoOtReceiver.mT1.size() * sizeof(block));
}

void WedprKkrtReceiver::step7GetFinalResult(const Matrix<block>& sendMatrix)
{
    for (u64 i = 0; i < recvMsgs.size(); ++i)
    {
        for (u64 j = 0; j < sendMatrix.cols(); ++j)
        {
            // We dont know which one is true
            recvMsgsResult[i] = recvMsgs[i] ^ sendMatrix(i, j);
        }
    }
}

void WedprKkrtReceiver::step7GetFinalResultWithDecMessage(const Matrix<block>& sendMatrix,
    std::vector<std::vector<block>>& enMessage, std::vector<std::vector<u8>>& hash)
{
    dataMessage.resize(choiceCount);
    // std::cout << "recvMsgs.size();" << recvMsgs.size() << std::endl;
    for (u64 i = 0; i < recvMsgs.size(); ++i)
    {
        // std::cout << "recvMsgs.size() i" << i << std::endl;
        // bool opt = true;
        // std::cout << "sendMatrix.cols()" << sendMatrix.cols() << std::endl;
        // std::cout << "sendMatrix.rows()" << sendMatrix.rows() << std::endl;
        for (u64 j = 0; j < sendMatrix.cols(); ++j)
        {
            recvMsgsResult[i] = recvMsgs[i] ^ sendMatrix(i, j);
            // ot message hash
            u8 keyHash[RandomOracle::HashSize];
            RandomOracle sha;
            sha.Update(recvMsgsResult[i]);
            sha.Final(keyHash);
            std::vector<u8> temp(keyHash, keyHash + RandomOracle::HashSize);

            if (temp == hash[j])
            {
                // decrypt message
                details::AESDec<details::AESTypes::NI> encKey(recvMsgsResult[i]);
                u64 length = enMessage[j].size();
                std::vector<block> data(length);
                // enMessage[i].resize(length);
                for (u64 m = 0; m < length; m++)
                {
                    encKey.ecbDecBlock(enMessage[j][m], data[m]);
                }
                dataMessage[i] = data;
                // opt = false;
                break;
            }
            // }
        }
    }
}

void WedprKkrtReceiver::step7GetFinalResultWithChoice(
    const Matrix<block>& sendMatrix, const std::vector<block>& optChoice)
{
    dataMessage.resize(choiceCount);
    for (u64 i = 0; i < recvMsgs.size(); ++i)
    {
        std::cout << "key = " << keys[i] << std::endl;
        bool opt = true;
        for (u64 j = 0; j < sendMatrix.cols() && opt; ++j)
        {
            recvMsgsResult[i] = recvMsgs[i] ^ sendMatrix(i, j);
            for (block choice : optChoice)
            {
                if (recvMsgsResult[i] == choice)
                {
                    // dataMessage[i][0] = recvMsgsResult[i];
                    dataMessage[i].push_back(recvMsgsResult[i]);
                    std::cout << "found recvMsgsResult[i] = " << recvMsgsResult[i] << std::endl;
                    opt = false;
                    break;
                }
            }
        }
    }
}


}  // namespace osuCrypto