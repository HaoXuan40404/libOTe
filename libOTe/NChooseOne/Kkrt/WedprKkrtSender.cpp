#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/WedprKkrtSender.h"

namespace osuCrypto
{
using namespace std;
    void WedprKkrtSender::step1(const u8* SPack, u8* RSPackResult){
        base.receiveSPack(recver, bv, msgsBase, prng, SPack, RSPackResult);
        kkrtNcoOtSender.setBaseOts(msgsBase, bv);
    }

    // seed maybe should use a pointer
    void WedprKkrtSender::step2(block& seed, u8* comm){
        seed = prng.get<block>();
        kkrtNcoOtSender.initStep1(numOTs, seed, comm);
    }

    void WedprKkrtSender::step3(block& mySeed, block& theirSeed,  Matrix<block>& mT, Matrix<block>& sendMatrix){
        std::array<u64, 2> choice{0, 0};
        kkrtNcoOtSender.initStep2(mySeed, theirSeed);
        std::cout<<"try copy mT"<<std::endl;
        std::cout<<"mT.size()* sizeof(block) = "<<mT.size()* sizeof(block)<<std::endl;
        memcpy(kkrtNcoOtSender.mCorrectionVals.data(), mT.data(), mT.size()* sizeof(block));
        std::cout<<"finish copy mT"<<std::endl;

        for (u64 i = 0; i < sendMessages.rows(); ++i)
        {
            for (u64 j = 0; j < sendMessages.cols(); ++j)
            {
                choice[0] = keys[j];
                // std::cout<<"sender choice = "<<choice[0]<<std::endl;
                kkrtNcoOtSender.encode(i, choice.data(), &sendMatrix(i, j));
                sendMatrix(i, j) = sendMatrix(i, j) ^ sendMessages(i, j);
            }
        }

    }

}