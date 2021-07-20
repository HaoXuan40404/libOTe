#include <iostream>
#include <string>
#include <vector>
#include "..//NChooseOne/Kkrt/WedprKkrtReceiver.h"
#include "..//NChooseOne/Kkrt/WedprKkrtSender.h"
// #include <jni.h>
#include <cryptoTools/Crypto/RandomOracle.h>

#include "./com_webank_wedpr_ot_kkrt_NativeInterface.h"
#include "cryptoTools/Common/Defines.h"
#include "jni_md.h"
#include "libOTe/Tools/Tools.h"

std::vector<osuCrypto::u64> JlongArrayToVectorU64(JNIEnv *env, jlongArray jArray) {
  int len = env->GetArrayLength(jArray);
    jlong *Jarray = env->GetLongArrayElements(jArray, JNI_FALSE);
    osuCrypto::u64* cArray = reinterpret_cast<osuCrypto::u64*>(Jarray);
    std::vector<osuCrypto::u64> cVector(cArray, cArray+len);
  return cVector;
}

std::vector<osuCrypto::u8> JbyteArrayToVectorU8(JNIEnv *env, jbyteArray jArray) {
  int len = env->GetArrayLength(jArray);
    unsigned char* byteVec = new unsigned char[len];
    env->GetByteArrayRegion (jArray, 0, len, reinterpret_cast<jbyte*>(byteVec));
    std::vector<osuCrypto::u8> cVector(byteVec, byteVec+len);
  return cVector;
}

#ifdef __cplusplus
extern "C" {
#endif

#define SIMPLEST_OT_PACK_BYTES 32


// generate sender
// return sender address
JNIEXPORT jlong Java_com_webank_wedpr_ot_kkrt_NativeInterface_newSender(JNIEnv *env, jclass obj, jlong choiceCountJ, jlong msgCountJ,jobjectArray dataMessageStringObj, jlongArray keyLongObj) {
    osuCrypto::u64 choiceCount = choiceCountJ;
    osuCrypto::u64 msgCount = msgCountJ;
    int dataLen = env->GetArrayLength(dataMessageStringObj);
    int keyLen = env->GetArrayLength(keyLongObj);
    if(dataLen != keyLen) {
        return 0;
    }
    std::vector<std::vector<osuCrypto::block>> dataBlock;
    // std::string dataStringArray[dataLen];
    for(int i = 0; i < dataLen; i++) {
        std::string dataString = env->GetStringUTFChars((jstring)env->GetObjectArrayElement(dataMessageStringObj, (jsize)i), JNI_FALSE);
        std::vector<osuCrypto::block> dataBlockEach;
        // osuCrypto::stringToBlockVec(const std::string &string, std::vector<block> &out);
        dataBlockEach = osuCrypto::stringToBlockVec(dataString);
        dataBlock.push_back(dataBlockEach);
    }

    std::vector<osuCrypto::u64> keys = JlongArrayToVectorU64(env, keyLongObj);

    // jlong *keyJarray = env->GetLongArrayElements(keyLongObj, JNI_FALSE);
    // osuCrypto::u64* keyArray = reinterpret_cast<osuCrypto::u64*>(keyJarray);
    // std::vector<osuCrypto::u64> keys(keyArray, keyArray+keyLen);
    osuCrypto::WedprKkrtSender *sender = new osuCrypto::WedprKkrtSender(choiceCount, msgCount, dataBlock, keys);
    // decrypt osuCrypto::block and generate random key
    sender->dataMessageToDecBlock();
    jlong handleSender = reinterpret_cast<jlong>(sender);
    return handleSender;
}

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_getSenderEncMessage
  (JNIEnv *env, jclass obj, jlong handleSender, jobjectArray enMessageObj, jobjectArray hashObj) {
    osuCrypto::WedprKkrtSender *sender;
    sender = reinterpret_cast<osuCrypto::WedprKkrtSender*>(handleSender);
    std::vector<std::vector<osuCrypto::block>> message = sender->enMessage;
    std::vector<std::vector<osuCrypto::u8>> hash = sender->hash;
    int messageLen = env->GetArrayLength(enMessageObj);
    int hashLen = env->GetArrayLength(hashObj);
    if(messageLen != sender->msgCount || hashLen != sender->msgCount ) {
      std::cout << "getSenderEncMessage length check failed!" << std::endl;
      return;
    }
    for(osuCrypto::u64 i = 0; i < sender->msgCount; i++) {
      // std::cout << "getSenderEncMessage start index = "<< i << std::endl;
      std::vector<osuCrypto::u64> enMessageVec = osuCrypto::ToU64Vector(message[i]);

      jlongArray enMessageArray = env->NewLongArray(enMessageVec.size());
      env->SetLongArrayRegion (enMessageArray, 0, enMessageVec.size(), reinterpret_cast<jlong*>(enMessageVec.data()));
      env->SetObjectArrayElement(enMessageObj,i, enMessageArray);
      jbyteArray hashArray = env->NewByteArray(20);
      env->SetByteArrayRegion (hashArray, 0, hash[i].size(), reinterpret_cast<jbyte*>(hash[i].data()));
      env->SetObjectArrayElement(hashObj,i,hashArray);
      // jstring enMessageStr = (jstring)env->GetObjectArrayElement(enMessageObj, i);
      // std::string enMessageCStrTest = env->GetStringUTFChars(enMessageStr, JNI_FALSE);
      // std::cout << "getSenderEncMessage enMessageCStrTest = "<< enMessageCStrTest << std::endl;
      // std::vector<osuCrypto::block> testRe = osuCrypto::stringToBlockVec(enMessageCStrTest);
      // std::cout << "getSenderEncMessage message[0] = "<< message[i][0] << std::endl;
      // std::cout << "getSenderEncMessage message[1] = "<< message[i][1] << std::endl;
      // // env->SetObjectField(jobject obj, jfieldID fieldID, jobject val)
      // // std::string enMessageCStr = env->GetStringUTFChars(enMessageStr, JNI_FALSE);
      // // jstring enMessageStr = (jstring)env->GetObjectArrayElement(enMessageObj, i);
      // jbyteArray hashArrayT = (jbyteArray)env->GetObjectArrayElement(hashObj, i);
      // std::vector<osuCrypto::u8> hashTre = JbyteArrayToVectorU8(env, hashArrayT);
      // for(int j = 0; j < 20; j++) {
      //   std::cout << "hashTre = "<< hashTre[j] << std::endl;
      //   std::cout << "hash[i] = "<< hash[i][j] << std::endl;
      // }
      // std::vector<osuCrypto::u64> messageLongArray = JlongArrayToVectorU64(env, message[i]);
    }
  }

JNIEXPORT jlong JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_newReceiver
  (JNIEnv *env, jclass obj, jlong choiceCountJ, jlong msgCountJ, jlongArray choiceLongObj) {
    osuCrypto::u64 choiceCount = choiceCountJ;
    osuCrypto::u64 msgCount = msgCountJ;

    std::vector<osuCrypto::u64> keys = JlongArrayToVectorU64(env, choiceLongObj);
    osuCrypto::WedprKkrtReceiver *recvers = new osuCrypto::WedprKkrtReceiver(choiceCount, msgCount, keys);
    jlong handleRecver = reinterpret_cast<jlong>(recvers);
    return handleRecver;
  }

#if defined(ENABLE_SIMPLESTOT)
JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step1ReceiverInitBaseOt
  (JNIEnv *env, jclass obj, jlong handleRecver, jbyteArray senderPackSeedObj, jlongArray receiverSeedObj) {
    osuCrypto::WedprKkrtReceiver *recver;
    recver = reinterpret_cast<osuCrypto::WedprKkrtReceiver*>(handleRecver);
    std::vector<osuCrypto::u8> senderPackSeed;
    recver->step1InitBaseOt(senderPackSeed);

    env->SetByteArrayRegion (senderPackSeedObj, 0, senderPackSeed.size(), reinterpret_cast<jbyte*>(senderPackSeed.data()));

    osuCrypto::block receiverSeed = recver->baseOtSeed;
    std::vector<osuCrypto::u64> receiverSeedVec = osuCrypto::ToU64Vector(receiverSeed);
    env->SetLongArrayRegion (receiverSeedObj, 0, receiverSeedVec.size(), reinterpret_cast<jlong*>(receiverSeedVec.data()));
  }

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step2SenderExtendSeedPack
  (JNIEnv *env, jclass obj, jlong handleSender, jbyteArray senderPackSeedObj, jlongArray receiverSeedObj, jbyteArray receiverPackObj) {
    osuCrypto::WedprKkrtSender *sender;
    sender = reinterpret_cast<osuCrypto::WedprKkrtSender*>(handleSender);

    std::vector<osuCrypto::u8> senderPackSeed = JbyteArrayToVectorU8(env, senderPackSeedObj);
    std::vector<osuCrypto::u64> receiverSeedByte = JlongArrayToVectorU64(env, receiverSeedObj);
    osuCrypto::block receiverSeed = osuCrypto::ToBlock(receiverSeedByte);

    std::vector<osuCrypto::u8> receiverPack;
    sender->step2ExtendSeedPack(receiverSeed,senderPackSeed, receiverPack);
    env->SetByteArrayRegion (receiverPackObj, 0, receiverPack.size(), reinterpret_cast<jbyte*>(receiverPack.data()));
  }
#endif

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step3ReceiverSetSeedPack
  (JNIEnv *env, jclass obj, jlong handleRecver, jbyteArray receiverPackObj) {
    osuCrypto::WedprKkrtReceiver *recver;
    recver = reinterpret_cast<osuCrypto::WedprKkrtReceiver*>(handleRecver);
    std::vector<osuCrypto::u8> receiverPack = JbyteArrayToVectorU8(env, receiverPackObj);
    recver->step3SetSeedPack(receiverPack);
  }

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step4SenderGenerateSeed
(JNIEnv *env, jclass obj, jlong handleSender, jlongArray senderSeedObj , jbyteArray senderSeedHashObj) {
  osuCrypto::WedprKkrtSender *sender;
  sender = reinterpret_cast<osuCrypto::WedprKkrtSender*>(handleSender);
  osuCrypto::block senderSeed;
  osuCrypto::u8 senderSeedHash[osuCrypto::RandomOracle::HashSize];
  sender->step4GenerateSeed(senderSeed, senderSeedHash);

  std::vector<osuCrypto::u64> senderSeedVec = osuCrypto::ToU64Vector(senderSeed);
  env->SetLongArrayRegion (senderSeedObj, 0, senderSeedVec.size(), reinterpret_cast<jlong*>(senderSeedVec.data()));
  env->SetByteArrayRegion (senderSeedHashObj, 0, osuCrypto::RandomOracle::HashSize, reinterpret_cast<jbyte*>(senderSeedHash));
}

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step5ReceiverInitMatrix
  (JNIEnv *env, jclass obj, jlong handleRecver, jlongArray senderSeedObj, jbyteArray senderSeedHashObj, jlongArray receiverSeedObj, jlongArray receiverMatrixObj) {
    osuCrypto::WedprKkrtReceiver *recver;
    recver = reinterpret_cast<osuCrypto::WedprKkrtReceiver*>(handleRecver);
    std::vector<osuCrypto::u64> senderSeedByte = JlongArrayToVectorU64(env, senderSeedObj);
    osuCrypto::block senderSeed = osuCrypto::ToBlock(senderSeedByte);

    std::vector<osuCrypto::u8> senderSeedHash = JbyteArrayToVectorU8(env, senderSeedHashObj);

    osuCrypto::block receiverSeed;
    osuCrypto::Matrix<osuCrypto::block> receiverMatrix(recver->choiceCount, recver->msgCount);
    recver->step5InitMatrix(senderSeed, senderSeedHash.data(), receiverSeed, receiverMatrix);

    std::vector<osuCrypto::u64> receiverSeedVec = osuCrypto::ToU64Vector(receiverSeed);
    env->SetLongArrayRegion (receiverSeedObj, 0, receiverSeedVec.size(), reinterpret_cast<jlong*>(receiverSeedVec.data()));
    std::vector<osuCrypto::u64> receiverMatrixVec = osuCrypto::MatrixToU64Vector(receiverMatrix);
    env->SetLongArrayRegion (receiverMatrixObj, 0, receiverMatrixVec.size(), reinterpret_cast<jlong*>(receiverMatrixVec.data()));
  }

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step6SenderSetMatrix
  (JNIEnv *env, jclass obj, jlong handleSender, jlongArray receiverSeedObj, jlongArray receiverMatrixObj, jlongArray senderSeedObj, jlongArray senderMatrixObj) {
    osuCrypto::WedprKkrtSender *sender;
    sender = reinterpret_cast<osuCrypto::WedprKkrtSender*>(handleSender);
    std::vector<osuCrypto::u64> receiverSeedByte = JlongArrayToVectorU64(env, receiverSeedObj);
    osuCrypto::block receiverSeed = osuCrypto::ToBlock(receiverSeedByte);

    std::vector<osuCrypto::u64> receiverMatrixByte = JlongArrayToVectorU64(env, receiverMatrixObj);
    osuCrypto::Matrix<osuCrypto::block> receiverMatrix = osuCrypto::U64VectorToMatrix(receiverMatrixByte, sender->choiceCount, 4);

    std::vector<osuCrypto::u64> senderSeedByte = JlongArrayToVectorU64(env, senderSeedObj);
    osuCrypto::block senderSeed = osuCrypto::ToBlock(senderSeedByte);

    osuCrypto::Matrix<osuCrypto::block> senderMatrix(sender->choiceCount, sender->msgCount);
    sender->step6SetMatrix(receiverSeed, receiverMatrix, senderSeed, senderMatrix);

    std::vector<osuCrypto::u64> senderMatrixVec = osuCrypto::MatrixToU64Vector(senderMatrix);
    env->SetLongArrayRegion (senderMatrixObj, 0, senderMatrixVec.size(), reinterpret_cast<jlong*>(senderMatrixVec.data()));
  }

JNIEXPORT void JNICALL Java_com_webank_wedpr_ot_kkrt_NativeInterface_step7ReceiverGetFinalResultWithDecMessage
  (JNIEnv *env, jclass obj, jlong handleRecver, jlongArray senderMatrixObj, jobjectArray enMessageObj, jobjectArray hashObj, jobjectArray dataObj) {
  osuCrypto::WedprKkrtReceiver *recver;
    recver = reinterpret_cast<osuCrypto::WedprKkrtReceiver*>(handleRecver);

    std::vector<osuCrypto::u64> senderMatrixVec = JlongArrayToVectorU64(env, senderMatrixObj);
    osuCrypto::Matrix<osuCrypto::block> senderMatrix = osuCrypto::U64VectorToMatrix(senderMatrixVec, recver->choiceCount, recver->msgCount);
    int messageLen = env->GetArrayLength(enMessageObj);
    int hashLen = env->GetArrayLength(hashObj);
    if(messageLen != recver->msgCount || hashLen != recver->msgCount ) {
      std::cout << "step7ReceiverGetFinalResultWithDecMessage length check failed!" << std::endl;
      return;
    }
    std::vector<std::vector<osuCrypto::block>> enMessageVec;
    std::vector<std::vector<osuCrypto::u8>> hash;
    for(osuCrypto::u64 i = 0; i < recver->msgCount; i++) {

      jlongArray enMessageArray = (jlongArray)env->GetObjectArrayElement(enMessageObj, i);
      std::vector<osuCrypto::u64> enMessageCVec = JlongArrayToVectorU64(env, enMessageArray);
      std::vector<osuCrypto::block> encBlock = osuCrypto::ToBlockVector(enMessageCVec);
      // std::cout << "step7ReceiverGetFinalResultWithDecMessage encBlock[0] = "<< encBlock[0] << std::endl;
      // std::cout << "step7ReceiverGetFinalResultWithDecMessage encBlock[1] = "<< encBlock[1] << std::endl;
      enMessageVec.push_back(encBlock);
      jbyteArray hashArray = (jbyteArray)env->GetObjectArrayElement(hashObj, i);
      std::vector<osuCrypto::u8> hashCVec = JbyteArrayToVectorU8(env, hashArray);
      hash.push_back(hashCVec);
    }

    recver->step7GetFinalResultWithDecMessage(senderMatrix, enMessageVec, hash);
    for(int i = 0; i < recver->choiceCount; i++){
        std::string result = blockVecToString(recver->dataMessage[i]);
        result[0] = '!';
        // std::stringstream buffer;
        // buffer<<result;
        // std::string resultChar = buffer.str();
        // char* result = blo(recver->dataMessage[i]);
        // char dataResult[] = "he2223啊232323232rtyuiojhgfgbn bgfrtrfyh";
        // char* resultD = new char[result.size()];

        //   std::cout << "result.size()= "<< result.size() << std::endl;

        // for(int k =0; k<result.size(); k++) {
        //   std::cout << "result byte= "<< (int)result[k] << std::endl;
        // }
        // memcpy(resultD, result, result.size());
        // char *cstr = new char[result.length() + 1];
        // strcpy(resultD, result.c_str());
        // std::cout << "recver.step7GetFinalResultWithDecMessage resultD = "<< resultD << std::endl;
        // std::cout << "recver.step7GetFinalResultWithDecMessage resultChar = "<< resultChar << std::endl;
        // std::cout << "recver.step7GetFinalResultWithDecMessage result = "<< result << std::endl;
        // jstring jResult = env->NewString(result.c_str(), result.length());
        // jstring jResult = env->NewStringUTF(result.data());
        // jstring jResult = env->NewStringUTF(resultChar.c_str());
        jstring jResult = env->NewStringUTF(result.c_str());
        // jstring jResult = env->NewStringUTF(what->c_str());
        // jstring jResult = env->NewString((jchar *)result.data(), result.size()/2);
        env->SetObjectArrayElement(dataObj, i, jResult);
        // jstring test = (jstring)env->GetObjectArrayElement(dataObj, i);
        // std::string testRe =  env->GetStringUTFChars(test, JNI_FALSE);
        // std::cout << "recver.step7GetFinalResultWithDecMessage testRe = "<< testRe << std::endl;
    }
  }

#ifdef __cplusplus
}
#endif