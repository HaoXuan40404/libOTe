#include "..//NChooseOne/Kkrt/WedprKkrtReceiver.h"
#include "..//NChooseOne/Kkrt/WedprKkrtSender.h"
#include <iostream>
#include <string>
#include <vector>
// #include <jni.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include "./com_webank_wedpr_ot_kkrt_NativeInterface.h"
#include "cryptoTools/Common/Defines.h"
#include "jni_md.h"
#include "libOTe/Tools/Tools.h"

std::vector<osuCrypto::u64> JlongArrayToVectorU64(JNIEnv* env, jlongArray jArray)
{
    int len = env->GetArrayLength(jArray);
    jlong* Jarray = env->GetLongArrayElements(jArray, JNI_FALSE);
    osuCrypto::u64* cArray = reinterpret_cast<osuCrypto::u64*>(Jarray);
    std::vector<osuCrypto::u64> cVector(cArray, cArray + len);
    return cVector;
}

std::vector<osuCrypto::u8> JbyteArrayToVectorU8(JNIEnv* env, jbyteArray jArray)
{
    int len = env->GetArrayLength(jArray);
    unsigned char* byteVec = new unsigned char[len];
    env->GetByteArrayRegion(jArray, 0, len, reinterpret_cast<jbyte*>(byteVec));
    std::vector<osuCrypto::u8> cVector(byteVec, byteVec + len);
    return cVector;
}

#ifdef __cplusplus
extern "C" {
#endif

#define SIMPLEST_OT_PACK_BYTES 32


// generate sender
// return sender address
JNIEXPORT jlong Java_com_webank_wedpr_ot_kkrt_NativeInterface_newSender(JNIEnv* env, jclass obj,
    jlong choiceCountJ, jlong msgCountJ, jobjectArray dataMessageStringObj, jlongArray keyLongObj)
{
    osuCrypto::u64 choiceCount = choiceCountJ;
    osuCrypto::u64 msgCount = msgCountJ;
    int dataLen = env->GetArrayLength(dataMessageStringObj);
    int keyLen = env->GetArrayLength(keyLongObj);
    if (dataLen != keyLen)
    {
        return 0;
    }
    std::vector<std::vector<osuCrypto::block>> dataBlock;
    for (int i = 0; i < dataLen; i++)
    {
        std::string dataString = env->GetStringUTFChars(
            (jstring)env->GetObjectArrayElement(dataMessageStringObj, (jsize)i), JNI_FALSE);
        std::vector<osuCrypto::block> dataBlockEach;
        dataBlockEach = osuCrypto::stringToBlockVec(dataString);
        dataBlock.push_back(dataBlockEach);
    }

    std::vector<osuCrypto::u64> keys = JlongArrayToVectorU64(env, keyLongObj);

    osuCrypto::WedprKkrtSender* sender =
        new osuCrypto::WedprKkrtSender(choiceCount, msgCount, dataBlock, keys);
    // decrypt osuCrypto::block and generate random key
    sender->dataMessageToDecBlock();
    jlong handleSender = reinterpret_cast<jlong>(sender);
    return handleSender;
}

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_deleteSender(
    JNIEnv* env, jclass obj, jlong handleSender)
{
    osuCrypto::WedprKkrtSender* sender;
    sender = reinterpret_cast<osuCrypto::WedprKkrtSender*>(handleSender);
    delete sender;
}

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_getSenderEncryptedMessage(
    JNIEnv* env, jclass obj, jlong handleSender, jobjectArray enMessageObj, jobjectArray hashObj)
{
    osuCrypto::WedprKkrtSender* sender;
    sender = reinterpret_cast<osuCrypto::WedprKkrtSender*>(handleSender);
    std::vector<std::vector<osuCrypto::block>> message = sender->enMessage;
    std::vector<std::vector<osuCrypto::u8>> hash = sender->hash;
    int messageLen = env->GetArrayLength(enMessageObj);
    int hashLen = env->GetArrayLength(hashObj);
    if (messageLen != (int)sender->msgCount || hashLen != (int)sender->msgCount)
    {
        std::cout << "getSenderEncMessage length check failed!" << std::endl;
        return;
    }
    for (osuCrypto::u64 i = 0; i < sender->msgCount; i++)
    {
        // std::cout << "getSenderEncMessage start index = "<< i << std::endl;
        std::vector<osuCrypto::u64> enMessageVec = osuCrypto::ToU64Vector(message[i]);

        jlongArray enMessageArray = env->NewLongArray(enMessageVec.size());
        env->SetLongArrayRegion(
            enMessageArray, 0, enMessageVec.size(), reinterpret_cast<jlong*>(enMessageVec.data()));
        env->SetObjectArrayElement(enMessageObj, i, enMessageArray);
        jbyteArray hashArray = env->NewByteArray(20);
        env->SetByteArrayRegion(
            hashArray, 0, hash[i].size(), reinterpret_cast<jbyte*>(hash[i].data()));
        env->SetObjectArrayElement(hashObj, i, hashArray);
    }
}

JNIEXPORT jlong JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_newReceiver(
    JNIEnv* env, jclass obj, jlong choiceCountJ, jlong msgCountJ, jlongArray choiceLongObj)
{
    osuCrypto::u64 choiceCount = choiceCountJ;
    osuCrypto::u64 msgCount = msgCountJ;

    std::vector<osuCrypto::u64> keys = JlongArrayToVectorU64(env, choiceLongObj);
    osuCrypto::WedprKkrtReceiver* recvers =
        new osuCrypto::WedprKkrtReceiver(choiceCount, msgCount, keys);
    jlong handleRecver = reinterpret_cast<jlong>(recvers);
    return handleRecver;
}

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_deleteReceiver(
    JNIEnv* env, jclass obj, jlong handleRecver)
{
    osuCrypto::WedprKkrtReceiver* recver;
    recver = reinterpret_cast<osuCrypto::WedprKkrtReceiver*>(handleRecver);
    delete recver;
}

#if defined(ENABLE_SIMPLESTOT)
JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step1ReceiverInitBaseOt(
    JNIEnv* env, jclass obj, jlong handleRecver, jbyteArray senderPackSeedObj,
    jlongArray receiverSeedObj)
{
    osuCrypto::WedprKkrtReceiver* recver;
    recver = reinterpret_cast<osuCrypto::WedprKkrtReceiver*>(handleRecver);
    std::vector<osuCrypto::u8> senderPackSeed;
    recver->step1InitBaseOt(senderPackSeed);

    env->SetByteArrayRegion(senderPackSeedObj, 0, senderPackSeed.size(),
        reinterpret_cast<jbyte*>(senderPackSeed.data()));

    osuCrypto::block receiverSeed = recver->baseOtSeed;
    std::vector<osuCrypto::u64> receiverSeedVec = osuCrypto::ToU64Vector(receiverSeed);
    env->SetLongArrayRegion(receiverSeedObj, 0, receiverSeedVec.size(),
        reinterpret_cast<jlong*>(receiverSeedVec.data()));
}

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step2SenderExtendSeedPack(
    JNIEnv* env, jclass obj, jlong handleSender, jbyteArray senderPackSeedObj,
    jlongArray receiverSeedObj, jbyteArray receiverPackObj)
{
    osuCrypto::WedprKkrtSender* sender;
    sender = reinterpret_cast<osuCrypto::WedprKkrtSender*>(handleSender);

    std::vector<osuCrypto::u8> senderPackSeed = JbyteArrayToVectorU8(env, senderPackSeedObj);
    std::vector<osuCrypto::u64> receiverSeedByte = JlongArrayToVectorU64(env, receiverSeedObj);
    osuCrypto::block receiverSeed = osuCrypto::ToBlock(receiverSeedByte);

    std::vector<osuCrypto::u8> receiverPack;
    sender->step2ExtendSeedPack(receiverSeed, senderPackSeed, receiverPack);
    env->SetByteArrayRegion(
        receiverPackObj, 0, receiverPack.size(), reinterpret_cast<jbyte*>(receiverPack.data()));
}
#endif

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step3ReceiverSetSeedPack(
    JNIEnv* env, jclass obj, jlong handleRecver, jbyteArray receiverPackObj)
{
    osuCrypto::WedprKkrtReceiver* recver;
    recver = reinterpret_cast<osuCrypto::WedprKkrtReceiver*>(handleRecver);
    std::vector<osuCrypto::u8> receiverPack = JbyteArrayToVectorU8(env, receiverPackObj);
    recver->step3SetSeedPack(receiverPack);
}

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step4SenderGenerateSeed(
    JNIEnv* env, jclass obj, jlong handleSender, jlongArray senderSeedObj,
    jbyteArray senderSeedHashObj)
{
    osuCrypto::WedprKkrtSender* sender;
    sender = reinterpret_cast<osuCrypto::WedprKkrtSender*>(handleSender);
    osuCrypto::block senderSeed;
    osuCrypto::u8 senderSeedHash[osuCrypto::RandomOracle::HashSize];
    sender->step4GenerateSeed(senderSeed, senderSeedHash);

    std::vector<osuCrypto::u64> senderSeedVec = osuCrypto::ToU64Vector(senderSeed);
    env->SetLongArrayRegion(
        senderSeedObj, 0, senderSeedVec.size(), reinterpret_cast<jlong*>(senderSeedVec.data()));
    env->SetByteArrayRegion(senderSeedHashObj, 0, osuCrypto::RandomOracle::HashSize,
        reinterpret_cast<jbyte*>(senderSeedHash));
}

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step5ReceiverInitMatrix(
    JNIEnv* env, jclass obj, jlong handleRecver, jlongArray senderSeedObj,
    jbyteArray senderSeedHashObj, jlongArray receiverSeedObj, jlongArray receiverMatrixObj)
{
    osuCrypto::WedprKkrtReceiver* recver;
    recver = reinterpret_cast<osuCrypto::WedprKkrtReceiver*>(handleRecver);
    std::vector<osuCrypto::u64> senderSeedByte = JlongArrayToVectorU64(env, senderSeedObj);
    osuCrypto::block senderSeed = osuCrypto::ToBlock(senderSeedByte);

    std::vector<osuCrypto::u8> senderSeedHash = JbyteArrayToVectorU8(env, senderSeedHashObj);

    osuCrypto::block receiverSeed;
    osuCrypto::Matrix<osuCrypto::block> receiverMatrix(recver->choiceCount, recver->msgCount);
    recver->step5InitMatrix(senderSeed, senderSeedHash.data(), receiverSeed, receiverMatrix);

    std::vector<osuCrypto::u64> receiverSeedVec = osuCrypto::ToU64Vector(receiverSeed);
    env->SetLongArrayRegion(receiverSeedObj, 0, receiverSeedVec.size(),
        reinterpret_cast<jlong*>(receiverSeedVec.data()));
    std::vector<osuCrypto::u64> receiverMatrixVec = osuCrypto::MatrixToU64Vector(receiverMatrix);
    env->SetLongArrayRegion(receiverMatrixObj, 0, receiverMatrixVec.size(),
        reinterpret_cast<jlong*>(receiverMatrixVec.data()));
}

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step6SenderSetMatrix(
    JNIEnv* env, jclass obj, jlong handleSender, jlongArray receiverSeedObj,
    jlongArray receiverMatrixObj, jlongArray senderSeedObj, jlongArray senderMatrixObj)
{
    osuCrypto::WedprKkrtSender* sender;
    sender = reinterpret_cast<osuCrypto::WedprKkrtSender*>(handleSender);
    std::vector<osuCrypto::u64> receiverSeedByte = JlongArrayToVectorU64(env, receiverSeedObj);
    osuCrypto::block receiverSeed = osuCrypto::ToBlock(receiverSeedByte);

    std::vector<osuCrypto::u64> receiverMatrixByte = JlongArrayToVectorU64(env, receiverMatrixObj);
    osuCrypto::Matrix<osuCrypto::block> receiverMatrix =
        osuCrypto::U64VectorToMatrix(receiverMatrixByte, sender->choiceCount, 4);

    std::vector<osuCrypto::u64> senderSeedByte = JlongArrayToVectorU64(env, senderSeedObj);
    osuCrypto::block senderSeed = osuCrypto::ToBlock(senderSeedByte);

    osuCrypto::Matrix<osuCrypto::block> senderMatrix(sender->choiceCount, sender->msgCount);
    sender->step6SetMatrix(receiverSeed, receiverMatrix, senderSeed, senderMatrix);

    std::vector<osuCrypto::u64> senderMatrixVec = osuCrypto::MatrixToU64Vector(senderMatrix);
    env->SetLongArrayRegion(senderMatrixObj, 0, senderMatrixVec.size(),
        reinterpret_cast<jlong*>(senderMatrixVec.data()));
}

JNIEXPORT void JNICALL
Java_com_webank_wedpr_ot_kkrt_NativeInterface_step7ReceiverGetFinalResultWithDecMessage(JNIEnv* env,
    jclass obj, jlong handleRecver, jlongArray senderMatrixObj, jobjectArray enMessageObj,
    jobjectArray hashObj, jobjectArray dataObj)
{
    osuCrypto::WedprKkrtReceiver* recver;
    recver = reinterpret_cast<osuCrypto::WedprKkrtReceiver*>(handleRecver);

    std::vector<osuCrypto::u64> senderMatrixVec = JlongArrayToVectorU64(env, senderMatrixObj);
    osuCrypto::Matrix<osuCrypto::block> senderMatrix =
        osuCrypto::U64VectorToMatrix(senderMatrixVec, recver->choiceCount, recver->msgCount);
    int messageLen = env->GetArrayLength(enMessageObj);
    int hashLen = env->GetArrayLength(hashObj);
    if (messageLen != (int)recver->msgCount || hashLen != (int)recver->msgCount)
    {
        std::cout << "step7ReceiverGetFinalResultWithDecMessage length check failed!" << std::endl;
        return;
    }
    std::vector<std::vector<osuCrypto::block>> enMessageVec;
    std::vector<std::vector<osuCrypto::u8>> hash;
    for (osuCrypto::u64 i = 0; i < recver->msgCount; i++)
    {
        jlongArray enMessageArray = (jlongArray)env->GetObjectArrayElement(enMessageObj, i);
        std::vector<osuCrypto::u64> enMessageCVec = JlongArrayToVectorU64(env, enMessageArray);
        std::vector<osuCrypto::block> encBlock = osuCrypto::ToBlockVector(enMessageCVec);
        // std::cout << "step7ReceiverGetFinalResultWithDecMessage encBlock[0] = "<< encBlock[0] <<
        // std::endl; std::cout << "step7ReceiverGetFinalResultWithDecMessage encBlock[1] = "<<
        // encBlock[1] << std::endl;
        enMessageVec.push_back(encBlock);
        jbyteArray hashArray = (jbyteArray)env->GetObjectArrayElement(hashObj, i);
        std::vector<osuCrypto::u8> hashCVec = JbyteArrayToVectorU8(env, hashArray);
        hash.push_back(hashCVec);
    }
    recver->step7GetFinalResultWithDecMessage(senderMatrix, enMessageVec, hash);
    for (int i = 0; i < (int)recver->choiceCount; i++)
    {
        std::string result = blockVecToString(recver->dataMessage[i]);
        if (result.size() > 0 && result[0] == char(00))
        {
            result.erase(0, 1);
        }

        jstring jResult = env->NewStringUTF(result.c_str());

        env->SetObjectArrayElement(dataObj, i, jResult);
    }
}

#ifdef __cplusplus
}
#endif