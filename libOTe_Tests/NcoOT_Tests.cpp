#include "OT_Tests.h"

#include "cryptoTools/Common/block.h"
#include "libOTe/TwoChooseOne/OTExtInterface.h"

#include "libOTe/Tools/LinearCode.h"
#include "libOTe/Tools/Tools.h"
#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Network/Session.h>


#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtReceiver.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtSender.h"

#include "Common.h"
#include "NcoOT_Tests.h"
#include "libOTe/Tools/bch511.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <sstream>

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/NChooseOne/NcoOtExt.h"
#include "libOTe_Tests/testData/code1280_BCH511.h"
#include "libOTe_Tests/testData/code128_BCH511.h"
#include "libOTe_Tests/testData/code256_BCH511.h"
#include "libOTe_Tests/testData/code384_BCH511.h"
#include "libOTe_Tests/testData/code640_BCH511.h"
#include <cryptoTools/Common/TestCollection.h>


// ppc
#include "libOTe/NChooseOne/Kkrt/WedprKkrtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/WedprKkrtSender.h"
#include <cryptoTools/Crypto/RandomOracle.h>


using namespace osuCrypto;


namespace tests_libOTe
{
void setBaseOts(NcoOtExtSender& sender, NcoOtExtReceiver& recv, Channel& sendChl, Channel& recvChl)
{
    u64 baseCount = sender.getBaseOTCount();

    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    PRNG prng0(ZeroBlock);
    baseChoice.randomize(prng0);

    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    auto a = std::async([&]() { sender.setBaseOts(baseRecv, baseChoice, sendChl); });
    recv.setBaseOts(baseSend, prng0, recvChl);
    a.get();
}


void testNco(NcoOtExtSender& sender, const u64& numOTs, PRNG& prng0, Channel& sendChl,
    NcoOtExtReceiver& recv, PRNG& prng1, Channel& recvChl)
{
    u64 stepSize = 33;
    std::vector<block> inputs(stepSize);
    setThreadName("Receiver");

    for (size_t j = 0; j < 10; j++)
    {
        // perform the init on each of the classes. should be performed concurrently
        auto thrd = std::thread([&]() {
            setThreadName("Sender");
            sender.init(numOTs, prng0, sendChl);
        });
        recv.init(numOTs, prng1, recvChl);
        thrd.join();

        std::vector<block> encoding1(stepSize), encoding2(stepSize);

        // Get the random OT messages
        for (u64 i = 0; i < numOTs; i += stepSize)
        {
            auto curStepSize = std::min<u64>(stepSize, numOTs - i);
            std::vector<u8> skips(curStepSize);

            prng0.get(inputs.data(), inputs.size());
            prng0.get((bool*)skips.data(), skips.size());

            for (u64 k = 0; k < curStepSize; ++k)
            {
                // The receiver MUST encode before the sender. Here we are only calling encode(...)
                // for a single i. But the receiver can also encode many i, but should only make one
                // call to encode for any given value of i.
                if (skips[k])
                {
                    recv.zeroEncode(i + k);
                }
                else
                {
                    recv.encode(i + k, &inputs[k], (u8*)&encoding1[k], sizeof(block));
                }
            }

            // This call will send to the other party the next "curStepSize " corrections to the
            // sender. If we had made more or less calls to encode above (for contigious i), then we
            // should replace curStepSize  with however many calls we made. In an extreme case, the
            // reciever can perform encode for i \in {0, ..., numOTs - 1}  and then call
            // sendCorrection(recvChl, numOTs).
            recv.sendCorrection(recvChl, curStepSize);

            // receive the next curStepSize  correction values. This allows the sender to now call
            // encode on the next curStepSize  OTs.
            sender.recvCorrection(sendChl, curStepSize);

            for (u64 k = 0; k < curStepSize; ++k)
            {
                // the sender can now call encode(i, ...) for k \in {0, ..., i}.
                // Lets encode the same input and then we should expect to
                // get the same encoding.
                sender.encode(i + k, &inputs[k], (u8*)&encoding2[k], sizeof(block));

                // check that we do in fact get the same value
                if (!skips[k] && neq(encoding1[k], encoding2[k]))
                    throw UnitTestFail("ot[" + std::to_string(i + k) + "] not equal " LOCATION);

                // In addition to the sender being able to obtain the same value as the receiver,
                // the sender can encode and other codeword. This should result in a different
                // encoding.
                inputs[k] = prng0.get<block>();

                sender.encode(i + k, &inputs[k], (u8*)&encoding2[k], sizeof(block));

                if (eq(encoding1[k], encoding2[k]))
                    throw UnitTestFail(LOCATION);
            }
        }
    }
}

void NcoOt_Kkrt_Test()
{
#ifdef ENABLE_KKRT
    setThreadName("Sender");

    // PRNG prng0(block(4253465, 3434565));
    // PRNG prng1(block(42532335, 334565));
    PRNG prng0(sysRandomSeed());
    PRNG prng1(sysRandomSeed());

    // std::cout<<prng0.get_block()<<std::endl;
    // std::cout<<prng1.get_block()<<std::endl;
    // 8d8d42bc7c02cd226bdc99f3e6cc914c
    // 5e2f6ccdee2d41d5e8e92bdde9e3b312


    // The total number that we wish to do
    u64 numOTs = 1030;

    KkrtNcoOtSender sender;
    KkrtNcoOtReceiver recv;
    // std::cout<<sender.mGens.data()<<std::endl;
    // std::cout<<recv.mGens.data()<<std::endl;

    // get up the parameters and get some information back.
    //  1) false = semi-honest
    //  2) 40  =  statistical security param.
    //  3) numOTs = number of OTs that we will perform
    sender.configure(false, 40, 128);
    recv.configure(false, 40, 128);
    // sender.mGens.resize(4*128);
    // recv.mGens.resize(4*128);
    // std::cout<<sender.mGens.data()<<std::endl;
    // std::cout<<recv.mGens.data()<<std::endl;


    // the number of base OT that need to be done
    u64 baseCount = sender.getBaseOTCount();
    // std::cout<<baseCount<<std::endl;

    // Fake some base OTs
    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);
    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i)
    {
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    // set up networking
    IOService ios;
    Session ep0(ios, "localhost", 1212, SessionMode::Server);
    Session ep1(ios, "localhost", 1212, SessionMode::Client);
    auto recvChl = ep1.addChannel();
    auto sendChl = ep0.addChannel();


    // set the base OTs
    sender.setBaseOts(baseRecv, baseChoice);
    recv.setBaseOts(baseSend);

    u64 stepSize = 10;
    std::vector<block> inputs(stepSize);

    for (size_t j = 0; j < 2; j++)
    {
        // perform the init on each of the classes. should be performed concurrently
        auto thrd = std::thread([&]() { sender.init(numOTs, prng0, sendChl); });
        recv.init(numOTs, prng1, recvChl);
        thrd.join();

        std::vector<block> encoding1(stepSize), encoding2(stepSize);

        // Get the random OT messages
        for (u64 i = 0; i < numOTs; i += stepSize)
        {
            prng0.get(inputs.data(), inputs.size());


            for (u64 k = 0; k < stepSize; ++k)
            {
                // The receiver MUST encode before the sender. Here we are only calling encode(...)
                // for a single i. But the receiver can also encode many i, but should only make one
                // call to encode for any given value of i.
                recv.encode(i + k, &inputs[k], (u8*)&encoding1[k], sizeof(block));
            }

            // This call will send to the other party the next "stepSize" corrections to the sender.
            // If we had made more or less calls to encode above (for contigious i), then we should
            // replace stepSize with however many calls we made. In an extreme case, the reciever
            // can perform encode for i \in {0, ..., numOTs - 1}  and then call
            // sendCorrection(recvChl, numOTs).
            recv.sendCorrection(recvChl, stepSize);

            // receive the next stepSize correction values. This allows the sender to now call
            // encode on the next stepSize OTs.
            sender.recvCorrection(sendChl, stepSize);

            for (u64 k = 0; k < stepSize; ++k)
            {
                // the sender can now call encode(i, ...) for k \in {0, ..., i}.
                // Lets encode the same input and then we should expect to
                // get the same encoding.
                sender.encode(i + k, &inputs[k], (u8*)&encoding2[k], sizeof(block));

                // check that we do in fact get the same value
                if (neq(encoding1[k], encoding2[k]))
                    throw UnitTestFail(LOCATION);

                // In addition to the sender being able to obtain the same value as the receiver,
                // the sender can encode and other codeword. This should result in a different
                // encoding.
                inputs[k] = prng0.get<block>();

                sender.encode(i + k, &inputs[k], (u8*)&encoding2[k], sizeof(block));

                if (eq(encoding1[k], encoding2[k]))
                    throw UnitTestFail(LOCATION);
            }
        }
    }


    // Double check that we can call split and perform the same tests.
    auto recv2Ptr = recv.split();
    auto send2Ptr = sender.split();

    auto& recv2 = *recv2Ptr;
    auto& send2 = *send2Ptr;

    for (size_t j = 0; j < 2; j++)
    {
        auto thrd = std::thread([&]() { send2.init(numOTs, prng0, sendChl); });

        recv2.init(numOTs, prng1, recvChl);

        thrd.join();


        for (u64 i = 0; i < numOTs; ++i)
        {
            block input = prng0.get<block>();

            block encoding1, encoding2;
            recv2.encode(i, &input, &encoding1);

            recv2.sendCorrection(recvChl, 1);
            send2.recvCorrection(sendChl, 1);

            send2.encode(i, &input, &encoding2);

            if (neq(encoding1, encoding2))
                throw UnitTestFail(LOCATION);

            input = prng0.get<block>();

            send2.encode(i, &input, &encoding2);

            if (eq(encoding1, encoding2))
                throw UnitTestFail(LOCATION);
        }
    }
#else
    throw UnitTestSkipped("ENALBE_KKRT is not defined.");
#endif
}

void NcoOt_Oos_Test()
{
#ifdef ENABLE_OOS
    setThreadName("Sender");

    PRNG prng0(block(4253465, 3434565));
    PRNG prng1(block(42532335, 334565));

    u64 numOTs = 128 * 16;

    IOService ios(0);
    Session ep0(ios, "localhost", 1212, SessionMode::Server);
    Session ep1(ios, "localhost", 1212, SessionMode::Client);
    auto recvChl = ep1.addChannel();
    auto sendChl = ep0.addChannel();

    OosNcoOtSender sender;
    OosNcoOtReceiver recv;

    sender.configure(true, 40, 50);
    recv.configure(true, 40, 50);

    if (1)
    {
        setBaseOts(sender, recv, sendChl, recvChl);
    }
    else
    {
        u64 baseCount = sender.getBaseOTCount();
        std::vector<block> baseRecv(baseCount);
        std::vector<std::array<block, 2>> baseSend(baseCount);
        BitVector baseChoice(baseCount);
        baseChoice.randomize(prng0);

        prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
        for (u64 i = 0; i < baseCount; ++i)
        {
            baseRecv[i] = baseSend[i][baseChoice[i]];
        }

        auto a = std::async([&]() { sender.setBaseOts(baseRecv, baseChoice, sendChl); });
        recv.setBaseOts(baseSend, prng0, recvChl);
        a.get();
    }


    testNco(sender, numOTs, prng0, sendChl, recv, prng1, recvChl);

    auto v = std::async([&] { recv.check(recvChl, toBlock(322334)); });

    try
    {
        sender.check(sendChl, toBlock(324));
    }
    catch (...)
    {
    }
    v.get();

    auto sender2 = sender.split();
    auto recv2 = recv.split();

    testNco(*sender2, numOTs, prng0, sendChl, *recv2, prng1, recvChl);

#else
    throw UnitTestSkipped("ENALBE_OOS is not defined.");
#endif
}


void NcoOt_Rr17_Test()
{
#ifdef ENABLE_RR
    setThreadName("Sender");


    PRNG prng0(block(4253465, 3434565));
    PRNG prng1(block(42532335, 334565));

    u64 numOTs = 80;
    u64 inputSize = 40;

    Rr17NcoOtSender sender;
    Rr17NcoOtReceiver recv;
    // u64  baseCount;
    sender.configure(true, 40, inputSize);
    recv.configure(true, 40, inputSize);

    IOService ios;
    Session ep0(ios, "localhost", 1212, SessionMode::Server);
    Session ep1(ios, "localhost", 1212, SessionMode::Client);
    auto recvChl = ep1.addChannel();
    auto sendChl = ep0.addChannel();

    setBaseOts(sender, recv, sendChl, recvChl);
    testNco(sender, numOTs, prng0, sendChl, recv, prng1, recvChl);

    auto sender2 = sender.split();
    auto recv2 = recv.split();

    testNco(*sender2, numOTs, prng0, sendChl, *recv2, prng1, recvChl);

#else
    throw UnitTestSkipped("ENALBE_RR is not defined.");
#endif
}


void NcoOt_chosen()
{
#ifdef ENABLE_OOS
    setThreadName("Sender");

    PRNG prng0(block(4253465, 3434565));
    PRNG prng1(block(42532335, 334565));

    u64 numOTs = 80;
    u64 inputSize = 8;

    OosNcoOtSender sender;
    OosNcoOtReceiver recv;
    // u64  baseCount;
    sender.configure(true, 40, inputSize);
    recv.configure(true, 40, inputSize);

    IOService ios;
    Session ep0(ios, "localhost", 1212, SessionMode::Server);
    Session ep1(ios, "localhost", 1212, SessionMode::Client);
    auto recvChl = ep1.addChannel();
    auto sendChl = ep0.addChannel();

    setBaseOts(sender, recv, sendChl, recvChl);

    auto messageCount = 1ull << inputSize;
    Matrix<block> sendMessage(numOTs, messageCount);
    std::vector<block> recvMessage(numOTs);

    prng0.get(sendMessage.data(), sendMessage.size());


    std::vector<u64> choices(numOTs);
    for (u64 i = 0; i < choices.size(); ++i)
    {
        choices[i] = prng0.get<u8>();
    }

    auto thrd = std::thread(
        [&]() { recv.receiveChosen(messageCount, recvMessage, choices, prng1, recvChl); });

    sender.sendChosen(sendMessage, prng0, sendChl);
    thrd.join();

    for (u64 i = 0; i < choices.size(); ++i)
    {
        if (neq(recvMessage[i], sendMessage(i, choices[i])))
            throw UnitTestFail("bad message " LOCATION);
    }

#else
    throw UnitTestSkipped("ENALBE_OOS is not defined.");
#endif
}


void NcoOt_genBaseOts_Test()
{
#if defined(LIBOTE_HAS_BASE_OT) && defined(ENABLE_OOS)
    IOService ios(0);
    Session ep0(ios, "127.0.0.1", 1212, SessionMode::Server);
    Session ep1(ios, "127.0.0.1", 1212, SessionMode::Client);
    Channel senderChannel = ep1.addChannel();
    Channel recvChannel = ep0.addChannel();

    OosNcoOtSender sender;
    OosNcoOtReceiver recv;
    auto inputSize = 50;
    sender.configure(true, 40, inputSize);
    recv.configure(true, 40, inputSize);

    auto thrd = std::thread([&]() {
        PRNG prng(ZeroBlock);
        recv.genBaseOts(prng, recvChannel);
    });

    PRNG prng(OneBlock);
    sender.genBaseOts(prng, senderChannel);
    thrd.join();

    for (u64 i = 0; i < sender.mGens.size(); ++i)
    {
        auto b = sender.mBaseChoiceBits[i];
        if (neq(sender.mGens[i].getSeed(), recv.mGens[i][b].getSeed()))
            throw RTE_LOC;

        if (eq(sender.mGens[i].getSeed(), recv.mGens[i][b ^ 1].getSeed()))
            throw RTE_LOC;
    }
#else
    throw UnitTestSkipped("no base OTs are enabled or ENABLE_OOS is not defined");
#endif
}


void Tools_LinearCode_Test()
{
    LinearCode code;


    // load the data at bch511_binary
    code.load(bch511_binary, sizeof(bch511_binary));

    // You can also load it from text
    // code.loadTxtFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.txt");

    // or binary file
    // code.loadBinFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.bin");

    // You can also write it in any format
    // code.writeTextFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.txt");
    // code.writeBinFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/bch511.bin");
    // code.writeBinCppFile(std::string(SOLUTION_DIR) + "/libOTe/Tools/new_bch511.h", "bch511");


    if (code.plaintextBitSize() != 76)
        throw UnitTestFail("bad input size reported by code");


    if (code.codewordBitSize() != 511)
        throw UnitTestFail("bad out size reported by code");

    std::vector<block> plainText(code.plaintextBlkSize(), AllOneBlock),
        codeword(code.codewordBlkSize());
    // gsl::span<u8>ss(plainText);
    code.encode(plainText, codeword);

    BitVector cw((u8*)codeword.data(), code.codewordBitSize());

    // expect all ones
    for (size_t i = 0; i < cw.size(); i++)
    {
        if (cw[i] == 0)
        {
            std::cout << cw << std::endl;
            std::cout << "expecting all ones" << std::endl;
            throw UnitTestFail(LOCATION);
        }
    }

    BitVector pt("1111111111111111111111111111111111111111111111111101111111111101111111111111");
    memset(plainText.data(), 0, plainText.size() * sizeof(block));
    memcpy(plainText.data(), pt.data(), pt.sizeBytes());


    code.encode(plainText, codeword);
    cw.resize(0);
    cw.append((u8*)codeword.data(), code.codewordBitSize());


    BitVector expected(
        "111111111111111111111111111111111111111111111111110111111111110111111111111110100001000111"
        "010001110001011001111111001001101000101000011111100110110111010110000010001001010100011001"
        "100111110111110010011100010111000010100000001100010001111001110000110110011111100100101101"
        "010001001011000101001100001111101010101001001001110100100110000110001010010100110011100001"
        "011001111001111000111000101111110101000110100010101011010001100000001101001111010101100110"
        "0011111111101001101111001111111101000010000011010111100011100");

    if (cw != expected)
    {
        std::cout << cw << std::endl;
        std::cout << expected << std::endl;
        throw UnitTestFail(LOCATION);
    }


    code.encode_bch511((u8*)plainText.data(), (u8*)codeword.data());
    cw.resize(0);
    cw.append((u8*)codeword.data(), code.codewordBitSize());


    expected = BitVector(
        "111111111111111111111111111111111111111111111111110111111111110111111111111110100001000111"
        "010001110001011001111111001001101000101000011111100110110111010110000010001001010100011001"
        "100111110111110010011100010111000010100000001100010001111001110000110110011111100100101101"
        "010001001011000101001100001111101010101001001001110100100110000110001010010100110011100001"
        "011001111001111000111000101111110101000110100010101011010001100000001101001111010101100110"
        "0011111111101001101111001111111101000010000011010111100011100");

    if (cw != expected)
    {
        std::cout << cw << std::endl;
        std::cout << expected << std::endl;
        throw UnitTestFail(LOCATION);
    }
}

void Tools_LinearCode_sub_Test()
{
    LinearCode code511, code128, code256, code384, code640, code1280;

    code511.load(bch511_binary, sizeof(bch511_binary));
    code128.load(code128_binary,
        sizeof(
            code128_binary));  // loadTxtFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code128_BCH511.txt");
    code256.load(code256_binary,
        sizeof(
            code256_binary));  // loadTxtFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code256_BCH511.txt");
    code384.load(code384_binary,
        sizeof(
            code384_binary));  // loadTxtFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code384_BCH511.txt");
    code640.load(code640_binary,
        sizeof(
            code640_binary));  // loadTxtFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code640_BCH511.txt");
    code1280.load(code1280_binary,
        sizeof(
            code1280_binary));  //.loadTxtFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code1280_BCH511.txt");

    // code128.writeBinCppFile( "C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code128_BCH511.h",
    // "code128_binary"); code256.writeBinCppFile(
    // "C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code256_BCH511.h", "code256_binary");
    // code384.writeBinCppFile( "C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code384_BCH511.h",
    // "code384_binary"); code640.writeBinCppFile(
    // "C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code640_BCH511.h", "code640_binary");
    // code1280.writeBinCppFile("C:/Users/peter/repo/libOTe/libOTe_Tests/testData/code1280_BCH511.h",
    // "code1280_binary");

    BitVector in(code511.plaintextBitSize()), out511(code511.codewordBitSize()),
        out128(code128.codewordBitSize()), out256(code256.codewordBitSize()),
        out384(code384.codewordBitSize()), out640(code640.codewordBitSize()),
        out1280(code1280.codewordBitSize());


    PRNG prng(ZeroBlock);

    for (u64 i = 0; i < 10; ++i)
    {
        in.randomize(prng);

        code511.encode(in.data(), out511.data());
        code128.encode(in.data(), out128.data());
        code256.encode(in.data(), out256.data());
        code384.encode(in.data(), out384.data());
        code640.encode(in.data(), out640.data());
        code1280.encode(in.data(), out1280.data());

        BitVector out511_128 = out511, out511_256 = out511, out511_384 = out511,
                  out511_640 = out511, out511_1280;

        u8 zero = 0;
        out511_640.append(&zero, 1);
        out511_640.append(out128);

        out511_1280.append(out640);
        out511_1280.append(out640);

        out511_128.resize(128);
        out511_256.resize(256);
        out511_384.resize(384);

        if (out511_128 != out128)
        {
            std::cout << "out511 " << out511_128 << std::endl;
            std::cout << "out128 " << out128 << std::endl;
            throw UnitTestFail(LOCATION);
        }

        if (out511_256 != out256)
        {
            std::cout << "out511 " << out511_256 << std::endl;
            std::cout << "out256 " << out256 << std::endl;
            throw UnitTestFail(LOCATION);
        }

        if (out511_384 != out384)
        {
            std::cout << "out511 " << out511_384 << std::endl;
            std::cout << "out384 " << out384 << std::endl;
            throw UnitTestFail(LOCATION);
        }

        if (out511_640 != out640)
        {
            std::cout << "out511 " << out511_640 << std::endl;
            std::cout << "out640 " << out640 << std::endl;

            for (u64 j = 0; j < 640; ++j)
            {
                if (out511_640[j] == out640[j])
                {
                    std::cout << " ";
                }
                else
                {
                    std::cout << "^" << j;
                }
            }

            std::cout << std::endl;
            throw UnitTestFail(LOCATION);
        }

        if (out511_1280 != out1280)
        {
            std::cout << "out511  " << out511_1280 << std::endl;
            std::cout << "out1280 " << out1280 << std::endl;
            throw UnitTestFail(LOCATION);
        }
    }
}

void Tools_LinearCode_rep_Test()
{
    LinearCode code;
    std::stringstream ss;
    ss << "1 40\n1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1";
    code.loadTxtFile(ss);

    u8 bit = 1;
    BitVector dest(40);
    code.encode(&bit, dest.data());


    for (u64 i = 0; i < 40; ++i)
    {
        if (dest[i] != 1)
            throw UnitTestFail(LOCATION);
    }
}

// void Wedpr_kkrt_ot_local_test()
// {
//     std::cout << "Wedpr_kkrt_ot_local_test" << std::endl;
//     // M times N choose 1
//     // numOTs M
//     // numChosenMsgs N
//     auto numOTs = 2;           // Messages.rows()
//     auto numChosenMsgs = 256;  // Messages.cols()
//     bool maliciousSecure = false;
//     u64 statSecParam = 40;
//     // u64 inputBitCount = 76;  // the kkrt protocol default to 128 but oos can only do 76.
//     u64 inputBitCount = 128;  // the kkrt protocol default to 128 but oos can only do 76.

//     // sender setup baseOT
//     PRNG prngS(sysRandomSeed());
//     KkrtNcoOtSender sender;
//     sender.configure(maliciousSecure, statSecParam, inputBitCount);

//     // recver setup baseOT
//     PRNG prngR(sysRandomSeed());
//     KkrtNcoOtReceiver recver;
//     recver.configure(maliciousSecure, statSecParam, inputBitCount);

//     // sender genBaseOT
//     auto countS = sender.getBaseOTCount();
//     std::vector<block> msgsS(countS);
//     DefaultBaseOT baseS;
//     RECEIVER recverBaseS;
//     BitVector bv(countS);
//     bv.randomize(prngS);


//     // recver genBaseOT
//     auto countR = recver.getBaseOTCount();
//     std::vector<std::array<block, 2>> msgsR(countR);
//     DefaultBaseOT baseR;

// #if defined(ENABLE_SIMPLESTOT)
//     EllipticCurve curve;
//     block baseOtSeed;
// #endif

//     // std::cout<<"baseR.sendSPack"<<std::endl;
// #ifdef ENABLE_SIMPLESTOT_ASM
//     baseR.sendSPack(senderBaseR, msgsR, prngR, SPack);
//     SENDER senderBaseR;
//     u8 SPack[SIMPLEST_OT_PACK_BYTES];
// #endif
//     std::vector<std::array<block, 2>> msgsBase;

//     // u8* RSPackResult[4*SIMPLEST_OT_PACK_BYTES];
//     u8* RSPackResult = (u8*)malloc(4 * SIMPLEST_OT_PACK_BYTES * countR * sizeof(u8));
//     // std::cout<<"baseS.receiveSPack"<<std::endl;
//     baseS.receiveSPack(recverBaseS, bv, msgsS, prngS, SPack, RSPackResult);

//     baseR.sendMessage(senderBaseR, msgsR, RSPackResult);

//     sender.setBaseOts(msgsS, bv);
//     recver.setBaseOts(msgsR);

//     // sender set kkrt message
//     // std::cout<<"sender set kkrt message"<<std::endl;
//     Matrix<block> sendMessagesEach(1, numChosenMsgs);
//     Matrix<block> sendMessages(numOTs, numChosenMsgs);
//     prngR.get(sendMessagesEach.data(), sendMessagesEach.size());


//     // sender init step1
//     // std::cout<<"sender init step1"<<std::endl;

//     block seedS = prngS.get<block>();
//     u8 comm[RandomOracle::HashSize];
//     // std::cout<<"sender init step1"<<std::endl;
//     // seedS comm is output
//     sender.initStep1(numOTs, seedS, comm);

//     // recver init step1
//     // std::cout<<"recver init step1"<<std::endl;
//     block seedR = prngS.get<block>();
//     recver.initStep1(numOTs, seedR, comm, seedS);
//     // std::cout<<"recver init step2"<<std::endl;
//     sender.initStep2(seedS, seedR);

//     std::vector<block> recvMsgs(numOTs);
//     std::vector<block> recvMsgsResult(numOTs);
//     std::vector<u64> choices(numOTs);

//     /// set recver random choose
//     // std::cout<<"set recver random choose"<<std::endl;
//     for (int i = 0; i < numOTs; ++i)
//     {
//         // choices[i] = prngR.get<u8>();
//         choices[i] = 13020199606358 + i;
//         // std::cout << "recver choices" << choices[i] << std::endl;
//     }

//     // recver encode
//     // std::cout<<"recver encode"<<std::endl;
//     std::array<u64, 2> choiceR{0, 0};

//     for (u64 i = 0; i < recvMsgs.size(); ++i)
//     {
//         // recver.mCorrectionIdx
//         choiceR[0] = choices[i];
//         std::cout << "recver choice = " << choices[i] << std::endl;
//         recver.encode(i, choiceR.data(), &recvMsgs[i]);
//     }

//     // fake meesage keys
//     std::vector<u64> keys;
//     for (int i = 0; i < numChosenMsgs; i++)
//     {
//         keys.push_back(13020199606308 + i);
//         // std::cout<<"key-"<<13020199606308+i<<std::endl;
//         // std::cout<<"idx-"<<i<<"=sendMessagesEach="<<sendMessagesEach[0][i]<<std::endl;
//     }
//     for (int i = 0; i < numOTs; i++)
//     {
//         for (int j = 0; j < numChosenMsgs; j++)
//         {
//             sendMessages[i][j] = sendMessagesEach[0][j];
//         }
//     }
//     // std::cout<<"sendMessages.cols()"<<sendMessages.cols()<<std::endl;
//     // std::cout<<"sendMessages.rows()"<<sendMessages.rows()<<std::endl;

//     // sender encode
//     // must be at least 128 bits.
//     // std::cout<<"start numCorrections = "<<sender.mCorrectionIdx<<std::endl;
//     // belive all message have been receive
//     sender.mCorrectionIdx = numOTs;
//     std::array<u64, 2> choiceS{0, 0};

//     // std::cout<<"sender.encode "<<std::endl;
//     Matrix<block> tempS(sendMessages.rows(), numChosenMsgs);
//     memcpy(sender.mCorrectionVals.data(), recver.mT1.data(), recver.mT1.size() * sizeof(block));

//     for (u64 i = 0; i < sendMessages.rows(); ++i)
//     {
//         for (u64 j = 0; j < sendMessages.cols(); ++j)
//         {
//             // jS = keys[j];
//             choiceS[0] = keys[j];
//             sender.encode(i, choiceS.data(), &tempS(i, j));
//             tempS(i, j) = tempS(i, j) ^ sendMessages(i, j);
//         }
//     }

//     // recver decode
//     // std::cout<<"recver.decode"<<std::endl;
//     for (u64 i = 0; i < recvMsgs.size(); ++i)
//     {
//         for (u64 j = 0; j < sendMessages.cols(); ++j)
//         {
//             // std::cout<<"index j = "<<j<<std::endl;
//             recvMsgsResult[i] = recvMsgs[i] ^ tempS(i, j);
//             // std::cout<<"recvMsgsResult = "<<recvMsgsResult[i]<<std::endl;
//         }
//     }
// }

// void Wedpr_kkrt_ot_choose_normal_test()
// {
//     std::cout << "Wedpr_kkrt_ot_choose_normal_test" << std::endl;
//     // M times N choose 1
//     // numOTs M
//     // numChosenMsgs N
//     auto numOTs = 2;           // Messages.rows()
//     auto numChosenMsgs = 500;  // Messages.cols()
//     bool maliciousSecure = false;
//     u64 statSecParam = 40;
//     u64 inputBitCount = 76;  // the kkrt protocol default to 128 but oos can only do 76.

//     // sender setup baseOT
//     PRNG prngS(sysRandomSeed());
//     KkrtNcoOtSender sender;
//     sender.configure(maliciousSecure, statSecParam, inputBitCount);

//     // recver setup baseOT
//     PRNG prngR(sysRandomSeed());
//     KkrtNcoOtReceiver recver;
//     recver.configure(maliciousSecure, statSecParam, inputBitCount);

//     // sender genBaseOT
//     auto countS = sender.getBaseOTCount();
//     std::vector<block> msgsS(countS);
//     DefaultBaseOT baseS;
//     RECEIVER recverBaseS;
//     BitVector bv(countS);
//     bv.randomize(prngS);
//     // sender.genBaseOtsStep1(baseS, PRNG &prng, std::vector<std::array<block, 2>> &msgs)


//     // recver genBaseOT
//     auto countR = recver.getBaseOTCount();
//     std::vector<std::array<block, 2>> msgsR(countR);
//     DefaultBaseOT baseR;

//     SENDER senderBaseR;
//     u8 SPack[SIMPLEST_OT_PACK_BYTES];
//     // std::cout<<"baseR.sendSPack"<<std::endl;
//     baseR.sendSPack(senderBaseR, msgsR, prngR, SPack);

//     // u8* RSPackResult[4*SIMPLEST_OT_PACK_BYTES];
//     u8* RSPackResult = (u8*)malloc(4 * SIMPLEST_OT_PACK_BYTES * countR * sizeof(u8));
//     // std::cout<<"baseS.receiveSPack"<<std::endl;
//     baseS.receiveSPack(recverBaseS, bv, msgsS, prngS, SPack, RSPackResult);

//     baseR.sendMessage(senderBaseR, msgsR, RSPackResult);

//     sender.setBaseOts(msgsS, bv);
//     recver.setBaseOts(msgsR);

//     // sender set kkrt message
//     // std::cout<<"sender set kkrt message"<<std::endl;
//     Matrix<block> sendMessagesEach(1, numChosenMsgs);
//     Matrix<block> sendMessages(numOTs, numChosenMsgs);
//     prngR.get(sendMessagesEach.data(), sendMessagesEach.size());
//     for (int i = 0; i < numChosenMsgs; i++)
//     {
//         // std::cout<<"idx i "<<i<<"sendMessagesEach="<<sendMessagesEach[0][i]<<std::endl;
//     }
//     for (int i = 0; i < numOTs; i++)
//     {
//         for (int j = 0; j < numChosenMsgs; j++)
//         {
//             sendMessages[i][j] = sendMessagesEach[0][j];
//         }
//     }

//     // sender init step1
//     // std::cout<<"sender init step1"<<std::endl;

//     // auto numOTExt = sendMessages.cols();
//     // std::cout<<"sendMessages.cols()"<<sendMessages.cols()<<std::endl;
//     // std::cout<<"sendMessages.rows()"<<sendMessages.rows()<<std::endl;

//     block seedS = prngS.get<block>();
//     u8 comm[RandomOracle::HashSize];
//     // std::cout<<"sender init step1"<<std::endl;
//     sender.initStep1(numOTs, seedS, comm);

//     // recver init step1
//     // std::cout<<"recver init step1"<<std::endl;
//     block seedR = prngS.get<block>();
//     recver.initStep1(numOTs, seedR, comm, seedS);
//     // std::cout<<"recver init step2"<<std::endl;
//     sender.initStep2(seedS, seedR);

//     std::vector<block> recvMsgs(numOTs);
//     std::vector<u64> choices(numOTs);
//     /// set recver random choose
//     // std::cout<<"set recver random choose"<<std::endl;
//     for (int i = 0; i < numOTs; ++i)
//     {
//         choices[i] = prngR.get<u8>();
//         // std::cout << "recver choices" << choices[i] << std::endl;
//     }

//     // recver encode
//     // std::cout<<"recver encode"<<std::endl;
//     std::array<u64, 2> choiceR{0, 0};
//     auto& jR = choiceR[0];
//     // block* t0Val = mT0.data() + mT0.stride() * otIdx;
//     for (u64 i = 0; i < recvMsgs.size(); ++i)
//     {
//         // recver.mCorrectionIdx
//         jR = choices[i];
//         recver.encode(i, choiceR.data(), &recvMsgs[i]);
//     }


//     // sender encode
//     // must be at least 128 bits.
//     // std::cout<<"start numCorrections = "<<sender.mCorrectionIdx<<std::endl;
//     // belive all message have been receive
//     sender.mCorrectionIdx = numOTs;
//     std::array<u64, 2> choiceS{0, 0};
//     u64& jS = choiceS[0];

//     std::cout << "sender.encode " << std::endl;
//     Matrix<block> tempS(sendMessages.rows(), numChosenMsgs);
//     // recver send mT1.data(),
//     memcpy(sender.mCorrectionVals.data(), recver.mT1.data(), recver.mT1.size() * sizeof(block));

//     for (u64 i = 0; i < sendMessages.rows(); ++i)
//     {
//         for (jS = 0; jS < sendMessages.cols(); ++jS)
//         {
//             sender.encode(i, choiceS.data(), &tempS(i, jS));
//             tempS(i, jS) = tempS(i, jS) ^ sendMessages(i, jS);
//         }
//     }

//     // recver decode
//     std::cout << "recver.decode" << std::endl;
//     for (u64 i = 0; i < recvMsgs.size(); ++i)
//     {
//         recvMsgs[i] = recvMsgs[i] ^ tempS(i, choices[i]);
//         std::cout << "recvMsgs = " << recvMsgs[i] << std::endl;
//     }
// }

void wedpr_kkrt_id_test()
{
    std::cout << "wedpr_kkrt_id_test" << std::endl;
    u64 choiceCount = 2;  // Messages.rows()
    u64 msgCount = 500;   // Messages.cols()

    // fake choice
    std::vector<u64> choices(choiceCount);
    for (u64 i = 0; i < choiceCount; i++)
    {
        // choices[i] = prngR.get<u8>();
        choices[i] = 13020199606358 + i;
        // std::cout << "recver set choices = " << choices[i] << std::endl;
    }

    // fake mssages
    Matrix<block> messages(choiceCount, msgCount);
    std::vector<u64> keys(msgCount);
    for (u64 i = 0; i < msgCount; i++)
    {
        // keys.push_back(13020199606308+i);
        keys[i] = 13020199606308 + i;
        // std::cout<<"key-"<<keys[i]<<std::endl;
        for (u64 j = 0; j < choiceCount; j++)
        {
            if (i > 255)
            {
                // messages[j][i] = toBlock("000000000000000");
                messages[j][i] = block(char(0), char(0), char(0), char(0), char(0), char(0),
                    char(0), char(0), char(0), char(0), char(0), char(0), char(0), char(0),
                    char(i / 255), char(i));
            }
            else
            {
                messages[j][i] =
                    block(char(0), char(0), char(0), char(0), char(0), char(0), char(0), char(0),
                        char(0), char(0), char(0), char(0), char(0), char(0), char(0), char(i));
            }
        }
        std::cout << "idx-" << keys[i] << "=messages=" << messages[0][i] << std::endl;
    }

    WedprKkrtSender sender(choiceCount, msgCount, messages, keys);
    WedprKkrtReceiver recver(choiceCount, msgCount, choices);

#if defined(ENABLE_SIMPLESTOT)
    std::vector<u8> senderPackSeed;
    std::cout << "recver.step1InitBaseOt" << std::endl;
    recver.step1InitBaseOt(senderPackSeed);

    // step2: sender generate receiverPack by senderPackSeed
    // sender::receiverPack ==> recver
    std::vector<u8> receiverPack;
    std::cout << "sender.step2ExtendSeedPack" << std::endl;
    sender.step2ExtendSeedPack(recver.baseOtSeed,senderPackSeed, receiverPack);

    // step3: recver set receiverPack
    // sender::receiverPack
    std::cout << "recver.step3SetSeedPack" << std::endl;
    // Base OT so extract step2 individual
    recver.step3SetSeedPack(receiverPack);
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    u8 senderPackSeed[SIMPLEST_OT_PACK_BYTES];
    std::cout << "recver.step1InitBaseOt" << std::endl;
    recver.step1InitBaseOt(senderPackSeed);

    // step2: sender generate receiverPack by senderPackSeed
    // sender::receiverPack ==> recver
    u8 receiverPack[4 * SIMPLEST_OT_PACK_BYTES * 512];
    std::cout << "sender.step2ExtendSeedPack" << std::endl;
    sender.step2ExtendSeedPack(senderPackSeed, receiverPack);

    // step3: recver set receiverPack
    // sender::receiverPack
    std::cout << "recver.step3SetSeedPack" << std::endl;
    // Base OT so extract step2 individual
    recver.step3SetSeedPack(receiverPack);
#endif


    // encode block

    block senderSeed;
    u8 senderSeedHash[RandomOracle::HashSize];
    // std::cout<<"sender.step2"<<std::endl;
    sender.step4GenerateSeed(senderSeed, senderSeedHash);
    // std::cout<<"sender.senderSeed ="<< senderSeed <<std::endl;
    // use Unsigned long
    // https://guava.dev/releases/snapshot-jre/api/docs/com/google/common/primitives/UnsignedLongs.html
    std::uint64_t first = senderSeed.as<std::uint64_t>()[0];
    std::uint64_t second = senderSeed.as<std::uint64_t>()[1];
    // std::cout<<"sender.first ="<< first <<std::endl;
    // std::cout<<"sender.second ="<< second <<std::endl;

    block senderSeed2 = block(second, first);
    // std::cout<<"sender.senderSeed2 ="<< senderSeed2 <<std::endl;


    // encode block Matrix<block>
    block receiverSeed;
    Matrix<block> receiverMatrix(choiceCount, msgCount);
    // std::cout<<"recver.step3"<<std::endl;
    recver.step5InitMatrix(senderSeed2, senderSeedHash, receiverSeed, receiverMatrix);

    // encode Matrix<block>
    Matrix<block> senderMatrix(choiceCount, msgCount);
    // std::cout<<"sender.step3"<<std::endl;
    sender.step6SetMatrix(receiverSeed, receiverMatrix, senderSeed2, senderMatrix);

    // std::cout<<"recver.step4"<<std::endl;
    recver.step7GetFinalResult(senderMatrix);
}

void wedpr_kkrt_aes_enc_test()
{
    std::cout << "wedpr_kkrt_aes_enc_test" << std::endl;
    u64 choiceCount = 10;  // Messages.rows()
    u64 msgCount = 10000;   // Messages.cols()

    // fake choice
    std::vector<u64> choices(choiceCount);
    for (u64 i = 0; i < choiceCount; i++)
    {
        // choices[i] = prngR.get<u8>();
        choices[i] = 13020199606358 + i;
        std::cout << "recver set choices = " << choices[i] << std::endl;
    }

    // fake mssages
    std::vector<std::vector<block>> dataMessage;
    dataMessage.resize(msgCount);
    std::vector<u64> keys(msgCount);
    for (u64 i = 0; i < msgCount; i++)
    {
        // keys.push_back(13020199606308+i);
        keys[i] = 13020199606308 + i;
        // std::cout<<"key-"<<keys[i]<<std::endl;
        // we test true message block length is 2
        std::string input = "test message index " + std::to_string(i);
        dataMessage[i] = stringToBlockVec(&input);
        // for (u64 j = 0; j < 3; j++)
        // {
        //     // block tmp = ;
        //     dataMessage[i].push_back(toBlock(i * 100000 + j));
        //     // dataMessage[i][j] = toBlock(i*100000+j);
        //     std::cout << "dataMessage[" << i << "][" << j << "]=" << dataMessage[i][j] << std::endl;
        // }
    }

    WedprKkrtSender sender(choiceCount, msgCount, dataMessage, keys);
    // decrypt block and generate random key
    sender.dataMessageToDecBlock();
    WedprKkrtReceiver recver(choiceCount, msgCount, choices);

    // step1: recver generate senderPackSeed
    // recver::senderPackSeed ==> sender
#if defined(ENABLE_SIMPLESTOT)
    std::vector<u8> senderPackSeed;
    std::cout << "recver.step1InitBaseOt" << std::endl;
    recver.step1InitBaseOt(senderPackSeed);

    // step2: sender generate receiverPack by senderPackSeed
    // sender::receiverPack ==> recver
    std::vector<u8> receiverPack;
    std::cout << "sender.step2ExtendSeedPack" << std::endl;
    sender.step2ExtendSeedPack(recver.baseOtSeed,senderPackSeed, receiverPack);

    // step3: recver set receiverPack
    // sender::receiverPack
    std::cout << "recver.step3SetSeedPack" << std::endl;
    // Base OT so extract step2 individual
    recver.step3SetSeedPack(receiverPack);
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    u8 senderPackSeed[SIMPLEST_OT_PACK_BYTES];
    std::cout << "recver.step1InitBaseOt" << std::endl;
    recver.step1InitBaseOt(senderPackSeed);

    // step2: sender generate receiverPack by senderPackSeed
    // sender::receiverPack ==> recver
    u8 receiverPack[4 * SIMPLEST_OT_PACK_BYTES * 512];
    std::cout << "sender.step2ExtendSeedPack" << std::endl;
    sender.step2ExtendSeedPack(senderPackSeed, receiverPack);

    // step3: recver set receiverPack
    // sender::receiverPack
    std::cout << "recver.step3SetSeedPack" << std::endl;
    // Base OT so extract step2 individual
    recver.step3SetSeedPack(receiverPack);
#endif

    // encode block
    // step4: sender generate senderSeed and senderSeedHash
    // sender::(senderSeed, senderSeedHash) ==> recver
    block senderSeed;
    u8 senderSeedHash[RandomOracle::HashSize];
    std::cout << "sender.step4GenerateSeed" << std::endl;
    sender.step4GenerateSeed(senderSeed, senderSeedHash);
    // use Unsigned long
    // https://guava.dev/releases/snapshot-jre/api/docs/com/google/common/primitives/UnsignedLongs.html
    // just show how to encode and decode block
    std::uint64_t first = senderSeed.as<std::uint64_t>()[0];
    std::uint64_t second = senderSeed.as<std::uint64_t>()[1];
    // std::cout<<"sender.first ="<< first <<std::endl;
    // std::cout<<"sender.second ="<< second <<std::endl;
    block senderSeed2 = block(second, first);
    // std::cout<<"sender.senderSeed2 ="<< senderSeed2 <<std::endl;


    // step5: recver init receiverMatrix by senderSeed and hash
    // recver::(receiverSeed, receiverMatrix) ==> sender
    block receiverSeed;
    Matrix<block> receiverMatrix(choiceCount, msgCount);
    std::cout << "recver.step5InitMatrix" << std::endl;
    recver.step5InitMatrix(senderSeed2, senderSeedHash, receiverSeed, receiverMatrix);

    // encode Matrix<block>
    // step6: sender init senderMatrix by seed and matrix
    // sender::(senderMatrix, enMessage, hash) ==> recver
    Matrix<block> senderMatrix(choiceCount, msgCount);
    std::cout << "sender.step6SetMatrix" << std::endl;
    sender.step6SetMatrix(receiverSeed, receiverMatrix, senderSeed2, senderMatrix);
    auto enMessage = sender.enMessage;
    auto hash = sender.hash;

    // step7: recver get final result
    std::cout << "recver.step7GetFinalResultWithDecMessage" << std::endl;
    recver.step7GetFinalResultWithDecMessage(senderMatrix, enMessage, hash);
    for(u64 i = 0; i < choiceCount; i++){
        std::string result = blockVecToString(recver.dataMessage[i]);
        std::cout << "recver.step7GetFinalResultWithDecMessage result = "<< result << std::endl;
    }
}

void wedpr_kkrt_vector_choice_test()
{
    std::cout << "wedpr_kkrt_vector_choice_test" << std::endl;
    u64 choiceCount = 2;  // Messages.rows()
    u64 msgCount = 500;   // Messages.cols()

    // fake choice
    std::vector<u64> choices(choiceCount);
    for (u64 i = 0; i < choiceCount; i++)
    {
        // choices[i] = prngR.get<u8>();
        choices[i] = 13020199606358 + i;
        std::cout << "recver set choices = " << choices[i] << std::endl;
    }

    // fake choice bucket, we believe blacklist only contain 5 status
    std::vector<block> maybeChoice;
    for (u64 i = 0; i < 5; i++)
    {
        maybeChoice.push_back(toBlock(i));
        std::cout << "maybeChoice = " << maybeChoice[i] << std::endl;
    }
    // fake mssages
    Matrix<block> messages(choiceCount, msgCount);
    std::vector<u64> keys(msgCount);
    for (u64 i = 0; i < msgCount; i++)
    {
        keys[i] = 13020199606308 + i;
        // std::cout<<"key-"<<keys[i]<<std::endl;
        for (u64 j = 0; j < choiceCount; j++)
        {
            messages[j][i] = maybeChoice[i % 5];
        }
        std::cout << "idx-" << keys[i] << "=messages=" << messages[0][i] << std::endl;
    }

    WedprKkrtSender sender(choiceCount, msgCount, messages, keys);
    // decrypt block and generate random key
    WedprKkrtReceiver recver(choiceCount, msgCount, choices);

    // step1: recver generate senderPackSeed
    // recver::senderPackSeed ==> sender
#if defined(ENABLE_SIMPLESTOT)
    std::vector<u8> senderPackSeed;
    std::cout << "recver.step1InitBaseOt" << std::endl;
    recver.step1InitBaseOt(senderPackSeed);

    // step2: sender generate receiverPack by senderPackSeed
    // sender::receiverPack ==> recver
    std::vector<u8> receiverPack;
    std::cout << "sender.step2ExtendSeedPack" << std::endl;
    sender.step2ExtendSeedPack(recver.baseOtSeed,senderPackSeed, receiverPack);

    // step3: recver set receiverPack
    // sender::receiverPack
    std::cout << "recver.step3SetSeedPack" << std::endl;
    // Base OT so extract step2 individual
    recver.step3SetSeedPack(receiverPack);
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    u8 senderPackSeed[SIMPLEST_OT_PACK_BYTES];
    std::cout << "recver.step1InitBaseOt" << std::endl;
    recver.step1InitBaseOt(senderPackSeed);

    // step2: sender generate receiverPack by senderPackSeed
    // sender::receiverPack ==> recver
    u8 receiverPack[4 * SIMPLEST_OT_PACK_BYTES * 512];
    std::cout << "sender.step2ExtendSeedPack" << std::endl;
    sender.step2ExtendSeedPack(senderPackSeed, receiverPack);

    // step3: recver set receiverPack
    // sender::receiverPack
    std::cout << "recver.step3SetSeedPack" << std::endl;
    // Base OT so extract step2 individual
    recver.step3SetSeedPack(receiverPack);
#endif


    // encode block
    // step4: sender generate senderSeed and senderSeedHash
    // sender::(senderSeed, senderSeedHash) ==> recver
    block senderSeed;
    u8 senderSeedHash[RandomOracle::HashSize];
    std::cout << "sender.step4GenerateSeed" << std::endl;
    sender.step4GenerateSeed(senderSeed, senderSeedHash);
    // use Unsigned long
    // https://guava.dev/releases/snapshot-jre/api/docs/com/google/common/primitives/UnsignedLongs.html
    // just show how to encode and decode block
    std::uint64_t first = senderSeed.as<std::uint64_t>()[0];
    std::uint64_t second = senderSeed.as<std::uint64_t>()[1];
    // std::cout<<"sender.first ="<< first <<std::endl;
    // std::cout<<"sender.second ="<< second <<std::endl;
    block senderSeed2 = block(second, first);
    // std::cout<<"sender.senderSeed2 ="<< senderSeed2 <<std::endl;


    // step5: recver init receiverMatrix by senderSeed and hash
    // recver::(receiverSeed, receiverMatrix) ==> sender
    block receiverSeed;
    Matrix<block> receiverMatrix(choiceCount, msgCount);
    std::cout << "recver.step5InitMatrix" << std::endl;
    recver.step5InitMatrix(senderSeed2, senderSeedHash, receiverSeed, receiverMatrix);

    // encode Matrix<block>
    // step6: sender init senderMatrix by seed and matrix
    // sender::(senderMatrix, enMessage, hash) ==> recver
    Matrix<block> senderMatrix(choiceCount, msgCount);
    std::cout << "sender.step6SetMatrix" << std::endl;
    sender.step6SetMatrix(receiverSeed, receiverMatrix, senderSeed2, senderMatrix);
    auto enMessage = sender.enMessage;
    auto hash = sender.hash;

    // step7: recver get final result
    std::cout << "recver.step7GetFinalResultWithChoice" << std::endl;
    recver.step7GetFinalResultWithChoice(senderMatrix, maybeChoice);
    // WedprKkrtSender *p = new WedprKkrtSender(choiceCount, msgCount, messages, keys);
    // std::stringstream ss;
    // ss << p;
    // std::string address = ss.str();
    // std::cout << "p address = "<< address << std::endl;
    // WedprKkrtSender *newP;
    // newP << address;

    // delete p;
}

void wedpr_kkrt_aes_enc_point_cast_test()
{
    std::cout << "wedpr_kkrt_aes_enc_point_cast_test" << std::endl;
    u64 choiceCount = 2;  // Messages.rows()
    u64 msgCount = 500;   // Messages.cols()

    // fake choice
    std::vector<u64> choices(choiceCount);
    for (u64 i = 0; i < choiceCount; i++)
    {
        // choices[i] = prngR.get<u8>();
        choices[i] = 13020199606358 + i;
        std::cout << "recver set choices = " << choices[i] << std::endl;
    }

    // fake mssages
    std::vector<std::vector<block>> dataMessage;
    dataMessage.resize(msgCount);
    std::vector<u64> keys(msgCount);
    for (u64 i = 0; i < msgCount; i++)
    {
        // keys.push_back(13020199606308+i);
        keys[i] = 13020199606308 + i;
        // std::cout<<"key-"<<keys[i]<<std::endl;
        // we test true message block length is 2
        // std::vector<block> tmp;
        std::string input = "test message index " + std::to_string(i);
        dataMessage[i] = stringToBlockVec(&input);
        // dataMessage[i] = tmp;
        std::cout << "dataMessage[" << i << "][0]=" << dataMessage[i][0] << std::endl;
        std::cout << "dataMessage[" << i << "][1]=" << dataMessage[i][1] << std::endl;
        std::string output = blockVecToString(dataMessage[i]);
        std::cout << "output = " << output << std::endl;
        // std::stringstream buffer;
        // buffer << dataMessage[i][1];
        // buffer << dataMessage[i][0];
        // std::string hex = buffer.str();
        // int len = hex.length();
        // std::string newString;
        // for(int i=len; i > 0; i-=2)
        // {
        //     std::string byte = hex.substr(i,2);
        //     if(byte == "00") {
        //         break;
        //     }
        //     char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        //     newString.push_back(chr);
        // }
        // std::cout << "newString = " << newString << std::endl;
        // for (u64 j = 0; j < 3; j++)
        // {
        //     // block tmp = ;
        //     dataMessage[i].push_back(toBlock(i * 100000 + j));
        //     // dataMessage[i][j] = toBlock(i*100000+j);
        //     std::cout << "dataMessage[" << i << "][" << j << "]=" << dataMessage[i][j] << std::endl;
        // }
    }
    WedprKkrtSender *senderPoint = new WedprKkrtSender(choiceCount, msgCount, dataMessage, keys);
    senderPoint->dataMessageToDecBlock();

    WedprKkrtReceiver *recverPoint = new WedprKkrtReceiver(choiceCount, msgCount, choices);

    std::uint64_t handleSender = reinterpret_cast<std::uint64_t>(senderPoint);
    std::uint64_t handleRecver = reinterpret_cast<std::uint64_t>(recverPoint);
    WedprKkrtSender *sender;
    WedprKkrtReceiver *recver;
    sender = reinterpret_cast<WedprKkrtSender*>(handleSender);
    recver = reinterpret_cast<WedprKkrtReceiver*>(handleRecver);

    // step1: recver generate senderPackSeed
    // recver::senderPackSeed ==> sender
#if defined(ENABLE_SIMPLESTOT)
    std::vector<u8> senderPackSeed;
    std::cout << "recver.step1InitBaseOt" << std::endl;
    recver->step1InitBaseOt(senderPackSeed);

    // step2: sender generate receiverPack by senderPackSeed
    // sender::receiverPack ==> recver
    std::vector<u8> receiverPack;
    std::cout << "sender.step2ExtendSeedPack" << std::endl;
    sender->step2ExtendSeedPack(recver->baseOtSeed,senderPackSeed, receiverPack);

    // step3: recver set receiverPack
    // sender::receiverPack
    std::cout << "recver.step3SetSeedPack" << std::endl;
    // Base OT so extract step2 individual
    recver->step3SetSeedPack(receiverPack);
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    u8 senderPackSeed[SIMPLEST_OT_PACK_BYTES];
    std::cout << "recver.step1InitBaseOt" << std::endl;
    recver->step1InitBaseOt(senderPackSeed);

    // step2: sender generate receiverPack by senderPackSeed
    // sender::receiverPack ==> recver
    u8 receiverPack[4 * SIMPLEST_OT_PACK_BYTES * 512];
    std::cout << "sender.step2ExtendSeedPack" << std::endl;
    sender->step2ExtendSeedPack(senderPackSeed, receiverPack);

    // step3: recver set receiverPack
    // sender::receiverPack
    std::cout << "recver.step3SetSeedPack" << std::endl;
    // Base OT so extract step2 individual
    recver->step3SetSeedPack(receiverPack);
#endif

    // encode block
    // step4: sender generate senderSeed and senderSeedHash
    // sender::(senderSeed, senderSeedHash) ==> recver
    block senderSeed;
    u8 senderSeedHash[RandomOracle::HashSize];
    std::cout << "sender.step4GenerateSeed" << std::endl;
    sender->step4GenerateSeed(senderSeed, senderSeedHash);
    // use Unsigned long
    // https://guava.dev/releases/snapshot-jre/api/docs/com/google/common/primitives/UnsignedLongs.html
    // just show how to encode and decode block
    std::uint64_t first = senderSeed.as<std::uint64_t>()[0];
    std::uint64_t second = senderSeed.as<std::uint64_t>()[1];
    // std::cout<<"sender.first ="<< first <<std::endl;
    // std::cout<<"sender.second ="<< second <<std::endl;
    block senderSeed2 = block(second, first);
    // std::cout<<"sender.senderSeed2 ="<< senderSeed2 <<std::endl;


    // step5: recver init receiverMatrix by senderSeed and hash
    // recver::(receiverSeed, receiverMatrix) ==> sender
    block receiverSeed;
    Matrix<block> receiverMatrix(choiceCount, msgCount);
    std::cout << "recver.step5InitMatrix" << std::endl;
    recver->step5InitMatrix(senderSeed2, senderSeedHash, receiverSeed, receiverMatrix);

    // encode Matrix<block>
    // step6: sender init senderMatrix by seed and matrix
    // sender::(senderMatrix, enMessage, hash) ==> recver
    Matrix<block> senderMatrix(choiceCount, msgCount);
    std::cout << "sender.step6SetMatrix" << std::endl;
    sender->step6SetMatrix(receiverSeed, receiverMatrix, senderSeed2, senderMatrix);
    auto enMessage = sender->enMessage;
    auto hash = sender->hash;

    // step7: recver get final result
    std::cout << "recver.step7GetFinalResultWithDecMessage" << std::endl;
    recver->step7GetFinalResultWithDecMessage(senderMatrix, enMessage, hash);
    for(u64 i = 0; i < choiceCount; i++){
        std::string result = blockVecToString(recver->dataMessage[i]);
        std::cout << "recver.step7GetFinalResultWithDecMessage result = "<< result << std::endl;
    }
    delete sender;
    delete recver;
    // block test = block(123456, 654321);
    // std::cout << "test = "<< test << std::endl;
    // std::vector<u8> converBytes = blockToBytesArray(test);
    // block testRec = bytesArrayToBlock(converBytes);
    // std::cout << "testRec = "<< testRec << std::endl;
}


void wedpr_kkrt_aes_enc_read_file_test()
{
    std::cout << "wedpr_kkrt_aes_enc_read_file_test" << std::endl;
    std::string choice_file_path = "./choice.csv";
    std::string message_file_path = "./message.csv";

    // u64 choiceCount = 10;  // Messages.rows()
    // u64 msgCount = 10000;   // Messages.cols()

    // fake choice
    // std::vector<u64> choices(choiceCount);
    // for (u64 i = 0; i < choiceCount; i++)
    // {
    //     // choices[i] = prngR.get<u8>();
    //     choices[i] = 13020199606358 + i;
    //     std::cout << "recver set choices = " << choices[i] << std::endl;
    // }

    // true choice
    std::vector<u64> choices;
    std::string line, word;
    // std::ifstream file1 (choice_file_path, ios::in);
    std::ifstream file1 (choice_file_path);
    while (getline(file1, line)) {
        std::istringstream iss(line);
        u64 value;
        iss >> value;
        choices.push_back(value);
        std::cout << "recver set choices = " << value << std::endl;
    }
    u64 choiceCount = choices.size();
    std::cout << "choiceCount = " << choiceCount << std::endl;


    std::vector<std::vector<block>> dataMessage;
    // dataMessage.resize(msgCount);
    std::vector<u64> keys;


    std::ifstream file2 (message_file_path);
    while (getline(file2, line)) {
        std::string delimiter_char = ",";
        size_t pos = 0;
        std::string token;
        while ((pos = line.find(delimiter_char)) != std::string::npos) {
            token = line.substr(0, pos);
            std::istringstream iss(line);
            u64 value;
            iss >> value;
            keys.push_back(value);
            // std::cout << token << std::endl;
            line.erase(0, pos + delimiter_char.length());
        }
        dataMessage.push_back(stringToBlockVec(&line));
    }
    u64 msgCount = keys.size();
    std::cout << "msgCount = " << msgCount << std::endl;


    WedprKkrtSender sender(choiceCount, msgCount, dataMessage, keys);
    // decrypt block and generate random key
    sender.dataMessageToDecBlock();
    WedprKkrtReceiver recver(choiceCount, msgCount, choices);

    // step1: recver generate senderPackSeed
    // recver::senderPackSeed ==> sender
#if defined(ENABLE_SIMPLESTOT)
    std::vector<u8> senderPackSeed;
    std::cout << "recver.step1InitBaseOt" << std::endl;
    recver.step1InitBaseOt(senderPackSeed);

    // step2: sender generate receiverPack by senderPackSeed
    // sender::receiverPack ==> recver
    std::vector<u8> receiverPack;
    std::cout << "sender.step2ExtendSeedPack" << std::endl;
    sender.step2ExtendSeedPack(recver.baseOtSeed,senderPackSeed, receiverPack);

    // step3: recver set receiverPack
    // sender::receiverPack
    std::cout << "recver.step3SetSeedPack" << std::endl;
    // Base OT so extract step2 individual
    recver.step3SetSeedPack(receiverPack);
#endif
#ifdef ENABLE_SIMPLESTOT_ASM
    u8 senderPackSeed[SIMPLEST_OT_PACK_BYTES];
    std::cout << "recver.step1InitBaseOt" << std::endl;
    recver.step1InitBaseOt(senderPackSeed);

    // step2: sender generate receiverPack by senderPackSeed
    // sender::receiverPack ==> recver
    u8 receiverPack[4 * SIMPLEST_OT_PACK_BYTES * 512];
    std::cout << "sender.step2ExtendSeedPack" << std::endl;
    sender.step2ExtendSeedPack(senderPackSeed, receiverPack);

    // step3: recver set receiverPack
    // sender::receiverPack
    std::cout << "recver.step3SetSeedPack" << std::endl;
    // Base OT so extract step2 individual
    recver.step3SetSeedPack(receiverPack);
#endif

    // encode block
    // step4: sender generate senderSeed and senderSeedHash
    // sender::(senderSeed, senderSeedHash) ==> recver
    block senderSeed;
    u8 senderSeedHash[RandomOracle::HashSize];
    std::cout << "sender.step4GenerateSeed" << std::endl;
    sender.step4GenerateSeed(senderSeed, senderSeedHash);
    // use Unsigned long
    // https://guava.dev/releases/snapshot-jre/api/docs/com/google/common/primitives/UnsignedLongs.html
    // just show how to encode and decode block
    std::uint64_t first = senderSeed.as<std::uint64_t>()[0];
    std::uint64_t second = senderSeed.as<std::uint64_t>()[1];
    // std::cout<<"sender.first ="<< first <<std::endl;
    // std::cout<<"sender.second ="<< second <<std::endl;
    block senderSeed2 = block(second, first);
    // std::cout<<"sender.senderSeed2 ="<< senderSeed2 <<std::endl;


    // step5: recver init receiverMatrix by senderSeed and hash
    // recver::(receiverSeed, receiverMatrix) ==> sender
    block receiverSeed;
    Matrix<block> receiverMatrix(choiceCount, msgCount);
    std::cout << "recver.step5InitMatrix" << std::endl;
    recver.step5InitMatrix(senderSeed2, senderSeedHash, receiverSeed, receiverMatrix);

    // encode Matrix<block>
    // step6: sender init senderMatrix by seed and matrix
    // sender::(senderMatrix, enMessage, hash) ==> recver
    Matrix<block> senderMatrix(choiceCount, msgCount);
    std::cout << "sender.step6SetMatrix" << std::endl;
    sender.step6SetMatrix(receiverSeed, receiverMatrix, senderSeed2, senderMatrix);
    auto enMessage = sender.enMessage;
    auto hash = sender.hash;

    // step7: recver get final result
    std::cout << "recver.step7GetFinalResultWithDecMessage" << std::endl;
    recver.step7GetFinalResultWithDecMessage(senderMatrix, enMessage, hash);
    for(u64 i = 0; i < choiceCount; i++){
        std::string result = blockVecToString(recver.dataMessage[i]);
        std::cout << "recver.step7GetFinalResultWithDecMessage id=CN" << recver.keys[i] << ", result = "<< result << std::endl;
    }
}


}  // namespace tests_libOTe