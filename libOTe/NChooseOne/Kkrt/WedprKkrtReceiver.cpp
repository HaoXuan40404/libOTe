#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/WedprKkrtReceiver.h"

namespace osuCrypto
{
using namespace std;
    void WedprKkrtReceiver::step1(u8* SPack){
        base.sendSPack(sender, msgsBase, prng, SPack);

    }

    void WedprKkrtReceiver::step2(const u8* RSPackResult) {
        base.sendMessage(sender, msgsBase, RSPackResult);
        kkrtNcoOtReceiver.setBaseOts(msgsBase);
    }

    void WedprKkrtReceiver::step3(const block& theirSeed, const u8* comm,block& MySeed, Matrix<block>& mT) {
        MySeed = prng.get<block>();
        kkrtNcoOtReceiver.initStep1(numOTs, MySeed, comm, theirSeed);
        std::array<u64, 2> choice{0, 0};
        for (u64 i = 0; i < recvMsgs.size(); ++i)
        {
            // recver.mCorrectionIdx
            std::cout<<"i = "<<i<<std::endl;
            choice[0] = keys[i];
            std::cout<<"recver choice = "<<choice[0]<<std::endl;
            kkrtNcoOtReceiver.encode(i, choice.data(), &recvMsgs[i]);
        }
        std::cout<<"kkrtNcoOtReceiver.mT1.size()* sizeof(block) = "<<kkrtNcoOtReceiver.mT1.size()* sizeof(block)<<std::endl;
        mT.resize(kkrtNcoOtReceiver.mT1.rows(), kkrtNcoOtReceiver.mT1.cols());
        memcpy(mT.data(), kkrtNcoOtReceiver.mT1.data(), kkrtNcoOtReceiver.mT1.size()* sizeof(block));
    }

    void WedprKkrtReceiver::step4(const Matrix<block>& sendMatrix) {
        for (u64 i = 0; i < recvMsgs.size(); ++i)
        {
            for (u64 j = 0; j < sendMatrix.cols(); ++j)
            {
                std::cout<<"index j = "<<j<<std::endl;
                recvMsgsResult[i] = recvMsgs[i] ^ sendMatrix(i, j);
                std::cout<<"recvMsgsResult = "<<recvMsgsResult[i]<<std::endl;
            }
        }
    }


}