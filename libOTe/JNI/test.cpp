// #include <iostream>
// #include <string>
// #include <vector>
// #include "..//NChooseOne/Kkrt/WedprKkrtReceiver.h"
// #include "..//NChooseOne/Kkrt/WedprKkrtSender.h"
// #include <jni.h>
// #include <cryptoTools/Crypto/RandomOracle.h>

// #include "./com_webank_wedpr_ot_kkrt_NativeInterface.h"

// #ifdef __cplusplus
// extern "C" {
// #endif
// void testTry() {
//     std::cout << "testTry" << std::endl;
// }

// #define SIMPLEST_OT_PACK_BYTES 32

// JNIEXPORT jlong Java_com_webank_wedpr_ot_kkrt_NativeInterface_newSender(JNIEnv *env, jobject obj, jlong choiceCountJ, jlong msgCountJ,jobjectArray dataMessageStringObj, jbyteArray keyBytesObj) {
//     std::cout << "Native method start. Printing Java_com_webank_wedpr_ot_kkrt_NativeInterface_newSender." << std::endl;
//     osuCrypto::u64 choiceCount = choiceCountJ;
//     osuCrypto::u64 msgCount = msgCountJ;
//     int len = env->GetArrayLength(dataMessageStringObj);
//     std::string stringArray[len];
//     for(int i = 0; i < len; i++) {
//         stringArray[i] = env->GetStringUTFChars((jstring)env->GetObjectArrayElement(dataMessageStringObj, (jsize)i), JNI_FALSE);
//     }
//     std::cout << "Native method called. Printing Java_com_webank_wedpr_ot_kkrt_NativeInterface_newSender." << std::endl;
//     std::vector<osuCrypto::u64> choices(choiceCount);
//     for (osuCrypto::u64 i = 0; i < choiceCount; i++)
//     {
//         // choices[i] = prngR.get<u8>();
//         choices[i] = 13020199606358 + i;
//     }
//     osuCrypto::WedprKkrtReceiver *recvers = new osuCrypto::WedprKkrtReceiver(choiceCount, msgCount, choices);
//     std::cout << "recver.msgCount = "<<recvers->msgCount << std::endl;

//     // fake mssages
//     std::vector<std::vector<osuCrypto::block>> dataMessage;
//     dataMessage.resize(msgCount);
//     std::vector<osuCrypto::u64> keys(msgCount);
//     for (osuCrypto::u64 i = 0; i < msgCount; i++)
//     {
//         // keys.push_back(13020199606308+i);
//         keys[i] = 13020199606308 + i;
//         // std::cout<<"key-"<<keys[i]<<std::endl;
//         // we test true message block length is 2
//         for (osuCrypto::u64 j = 0; j < 3; j++)
//         {
//             // block tmp = ;
//             dataMessage[i].push_back(osuCrypto::toBlock(i * 100000 + j));
//             // dataMessage[i][j] = toBlock(i*100000+j);
//             std::cout << "dataMessage[" << i << "][" << j << "]=" << dataMessage[i][j] << std::endl;
//         }
//     }

//     osuCrypto::WedprKkrtSender sender(choiceCount, msgCount, dataMessage, keys);
//     // decrypt block and generate random key
//     sender.dataMessageToDecBlock();
//     osuCrypto::WedprKkrtReceiver recver(choiceCount, msgCount, choices);

//     // step1: recver generate senderPackSeed
//     // recver::senderPackSeed ==> sender
//     osuCrypto::u8 senderPackSeed[SIMPLEST_OT_PACK_BYTES];
//     std::cout << "recver.step1InitBaseOt" << std::endl;
//     recver.step1InitBaseOt(senderPackSeed);

//     // step2: sender generate receiverPack by senderPackSeed
//     // sender::receiverPack ==> recver
//     osuCrypto::u8 receiverPack[4 * SIMPLEST_OT_PACK_BYTES * 512];
//     std::cout << "sender.step2ExtendSeedPack" << std::endl;
//     sender.step2ExtendSeedPack(senderPackSeed, receiverPack);

//     // step3: recver set receiverPack
//     // sender::receiverPack
//     std::cout << "recver.step3SetSeedPack" << std::endl;
//     // Base OT so extract step2 individual
//     recver.step3SetSeedPack(receiverPack);

//     // encode block
//     // step4: sender generate senderSeed and senderSeedHash
//     // sender::(senderSeed, senderSeedHash) ==> recver
//     osuCrypto::block senderSeed;
//     osuCrypto::u8 senderSeedHash[osuCrypto::RandomOracle::HashSize];
//     std::cout << "sender.step4GenerateSeed" << std::endl;
//     sender.step4GenerateSeed(senderSeed, senderSeedHash);
//     // use Unsigned long
//     // https://guava.dev/releases/snapshot-jre/api/docs/com/google/common/primitives/UnsignedLongs.html
//     // just show how to encode and decode block
//     std::uint64_t first = senderSeed.as<std::uint64_t>()[0];
//     std::uint64_t second = senderSeed.as<std::uint64_t>()[1];
//     // std::cout<<"sender.first ="<< first <<std::endl;
//     // std::cout<<"sender.second ="<< second <<std::endl;
//     osuCrypto::block senderSeed2 = osuCrypto::block(second, first);
//     // std::cout<<"sender.senderSeed2 ="<< senderSeed2 <<std::endl;


//     // step5: recver init receiverMatrix by senderSeed and hash
//     // recver::(receiverSeed, receiverMatrix) ==> sender
//     osuCrypto::block receiverSeed;
//     osuCrypto::Matrix<osuCrypto::block> receiverMatrix(choiceCount, msgCount);
//     std::cout << "recver.step5InitMatrix" << std::endl;
//     recver.step5InitMatrix(senderSeed2, senderSeedHash, receiverSeed, receiverMatrix);

//     // encode Matrix<block>
//     // step6: sender init senderMatrix by seed and matrix
//     // sender::(senderMatrix, enMessage, hash) ==> recver
//     osuCrypto::Matrix<osuCrypto::block> senderMatrix(choiceCount, msgCount);
//     std::cout << "sender.step6SetMatrix" << std::endl;
//     sender.step6SetMatrix(receiverSeed, receiverMatrix, senderSeed2, senderMatrix);
//     auto enMessage = sender.enMessage;
//     auto hash = sender.hash;

//     // step7: recver get final result
//     std::cout << "recver.step7GetFinalResultWithDecMessage" << std::endl;
//     recver.step7GetFinalResultWithDecMessage(senderMatrix, enMessage, hash);

//     // int len = env->GetArrayLength(dataMessageBytesObj);
//     // unsigned char* byteVec = new unsigned char[len];
//     // env->GetByteArrayRegion (dataMessageBytesObj, 0, len, reinterpret_cast<jbyte*>(byteVec));

// }

// // JNIEXPORT void JNICALL Java_in_derros_jni_Utilities_printMethod
// //         (JNIEnv *env, jobject obj) {
// //     std::cout << "Native method called. Printing garbage." << std::endl;
// // }
// #ifdef __cplusplus
// }
// #endif