#include "SimplestOT.h"


#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Network/Channel.h>

#ifdef ENABLE_SIMPLESTOT
#ifdef ENABLE_RELIC
#include <cryptoTools/Crypto/RCurve.h>
#else
#include <cryptoTools/Crypto/Curve.h>
#endif

namespace osuCrypto
{
#ifdef ENABLE_RELIC
using Curve = REllipticCurve;
using Point = REccPoint;
using Brick = REccPoint;
using Number = REccNumber;
#else
using Curve = EllipticCurve;
using Point = EccPoint;
using Brick = EccBrick;
using Number = EccNumber;
#endif

void SimplestOT::receive(const BitVector& choices, span<block> msg, PRNG& prng, Channel& chl)
{
    Curve curve;
    Point g = curve.getGenerator();
    u64 pointSize = g.sizeBytes();
    u64 n = msg.size();

    block comm = oc::ZeroBlock, seed;
    Point A(curve);
    std::vector<u8> buff(pointSize + mUniformOTs * sizeof(block)), hashBuff(pointSize);
    chl.recv(buff.data(), buff.size());
    A.fromBytes(buff.data());

    if (mUniformOTs)
        memcpy(&comm, buff.data() + pointSize, sizeof(block));

    buff.resize(pointSize * n);
    auto buffIter = buff.data();

    std::vector<Number> b;
    b.reserve(n);
    ;
    std::array<Point, 2> B{curve, curve};
    for (u64 i = 0; i < n; ++i)
    {
        b.emplace_back(curve, prng);
        B[0] = g * b[i];
        B[1] = A + B[0];

        B[choices[i]].toBytes(buffIter);
        buffIter += pointSize;
    }

    chl.asyncSend(std::move(buff));
    if (mUniformOTs)
    {
        chl.recv(seed);
        if (neq(comm, mAesFixedKey.ecbEncBlock(seed) ^ seed))
            throw std::runtime_error("bad decommitment " LOCATION);
    }

    for (u64 i = 0; i < n; ++i)
    {
        B[0] = A * b[i];
        B[0].toBytes(hashBuff.data());
        RandomOracle ro(sizeof(block));
        ro.Update(hashBuff.data(), hashBuff.size());
        if (mUniformOTs)
            ro.Update(seed);
        ro.Final(msg[i]);
    }
}

void SimplestOT::send(span<std::array<block, 2>> msg, PRNG& prng, Channel& chl)
{
    Curve curve;
    Point g = curve.getGenerator();
    u64 pointSize = g.sizeBytes();
    u64 n = msg.size();

    block seed = prng.get<block>();
    Number a(curve, prng);
    Point A = g * a;
    std::vector<u8> buff(pointSize + mUniformOTs * sizeof(block)), hashBuff(pointSize);
    A.toBytes(buff.data());

    if (mUniformOTs)
    {
        // commit to the seed
        auto comm = mAesFixedKey.ecbEncBlock(seed) ^ seed;
        memcpy(buff.data() + pointSize, &comm, sizeof(block));
    }

    chl.asyncSend(std::move(buff));

    buff.resize(pointSize * n);
    chl.recv(buff.data(), buff.size());

    if (mUniformOTs)
    {
        // decommit to the seed now that we have their messages.
        chl.send(seed);
    }

    auto buffIter = buff.data();

    A *= a;
    Point B(curve), Ba(curve);
    for (u64 i = 0; i < n; ++i)
    {
        B.fromBytes(buffIter);
        buffIter += pointSize;

        Ba = B * a;
        Ba.toBytes(hashBuff.data());
        RandomOracle ro(sizeof(block));
        ro.Update(hashBuff.data(), hashBuff.size());
        if (mUniformOTs)
            ro.Update(seed);
        ro.Final(msg[i][0]);

        Ba -= A;
        Ba.toBytes(hashBuff.data());
        ro.Reset();
        ro.Update(hashBuff.data(), hashBuff.size());
        if (mUniformOTs)
            ro.Update(seed);
        ro.Final(msg[i][1]);
    }
}

void SimplestOT::sendSPack(Curve& curve, Number&a,  PRNG& prng, std::vector<u8>& S_pack, block& seed)
{
    Point g = curve.getGenerator();
    u64 pointSize = g.sizeBytes();

    seed = prng.get<block>();
    // Number a(curve, prng);
    // Number a(curve);
    // std::cout << "saaaaaaa"<< a << std::endl;
    // myTestA = a;
    Point A = g * a;
    std::vector<u8> buff(pointSize + mUniformOTs * sizeof(block)), hashBuff(pointSize);
    A.toBytes(buff.data());

    if (mUniformOTs)
    {
        // commit to the seed
        auto comm = mAesFixedKey.ecbEncBlock(seed) ^ seed;
        memcpy(buff.data() + pointSize, &comm, sizeof(block));
    }
    S_pack = buff;
}

void SimplestOT::sendMessage(Curve& curve, EccNumber& a, span<std::array<block, 2>> msg, block& seed, std::vector<u8>& RS_pack_result)
{
    Point g = curve.getGenerator();
    u64 pointSize = g.sizeBytes();
    u64 n = msg.size();


    // Number a(curve, prng);
    // Number a(curve);
    // Number a = myTestA;
    // std::cout << "saaaaaaa"<< a << std::endl;
    Point A = g * a;
    std::vector<u8> buff(pointSize + mUniformOTs * sizeof(block)), hashBuff(pointSize);
    A.toBytes(buff.data());

    auto buffIter = RS_pack_result.data();

    A *= a;
    Point B(curve), Ba(curve);
    for (u64 i = 0; i < n; ++i)
    {
        B.fromBytes(buffIter);
        buffIter += pointSize;

        Ba = B * a;
        Ba.toBytes(hashBuff.data());
        RandomOracle ro(sizeof(block));
        ro.Update(hashBuff.data(), hashBuff.size());
        if (mUniformOTs)
            ro.Update(seed);
        ro.Final(msg[i][0]);

        Ba -= A;
        Ba.toBytes(hashBuff.data());
        ro.Reset();
        ro.Update(hashBuff.data(), hashBuff.size());
        if (mUniformOTs)
            ro.Update(seed);
        ro.Final(msg[i][1]);
    }
}

void SimplestOT::receiveSPack(Curve& curve, const BitVector& choices, span<block> msg, PRNG& prng, const block& seed, std::vector<u8>& S_pack, std::vector<u8>& RS_pack_result)
{
    Point g = curve.getGenerator();
    u64 pointSize = g.sizeBytes();
    u64 n = msg.size();

    block comm = oc::ZeroBlock;
    Point A(curve);
    std::vector<u8> buff(pointSize + mUniformOTs * sizeof(block)), hashBuff(pointSize);
    buff = S_pack;
    A.fromBytes(buff.data());

    if (mUniformOTs)
        memcpy(&comm, buff.data() + pointSize, sizeof(block));

    buff.resize(pointSize * n);
    auto buffIter = buff.data();

    std::vector<Number> b;
    b.reserve(n);
    ;
    std::array<Point, 2> B{curve, curve};
    for (u64 i = 0; i < n; ++i)
    {
        b.emplace_back(curve, prng);
        B[0] = g * b[i];
        B[1] = A + B[0];

        B[choices[i]].toBytes(buffIter);
        buffIter += pointSize;
    }
    RS_pack_result = buff;
    // chl.asyncSend(std::move(buff));
    if (mUniformOTs)
    {
        // chl.recv(seed);
        if (neq(comm, mAesFixedKey.ecbEncBlock(seed) ^ seed))
            throw std::runtime_error("bad decommitment " LOCATION);
    }

    for (u64 i = 0; i < n; ++i)
    {
        B[0] = A * b[i];
        B[0].toBytes(hashBuff.data());
        RandomOracle ro(sizeof(block));
        ro.Update(hashBuff.data(), hashBuff.size());
        if (mUniformOTs)
            ro.Update(seed);
        ro.Final(msg[i]);
    }
}

}  // namespace osuCrypto
#endif

#ifdef ENABLE_SIMPLESTOT_ASM
extern "C" {
#include "../SimplestOT/cpucycles.h"
#include "../SimplestOT/ot_config.h"
#include "../SimplestOT/ot_receiver.h"
#include "../SimplestOT/ot_sender.h"
#include "../SimplestOT/randombytes.h"
}
namespace osuCrypto
{
rand_source makeRandSource(PRNG& prng)
{
    rand_source rand;
    rand.get = [](void* ctx, unsigned char* dest, unsigned long long length) {
        PRNG& prng = *(PRNG*)ctx;
        prng.get(dest, length);
    };
    rand.ctx = &prng;

    return rand;
}

void AsmSimplestOT::receive(const BitVector& choices, span<block> msg, PRNG& prng, Channel& chl)
{
    RECEIVER receiver;

    u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
    u8 keys[4][SIMPLEST_OT_HASHBYTES];
    u8 cs[4];

    chl.recv(receiver.S_pack, sizeof(receiver.S_pack));
    receiver_procS(&receiver);

    receiver_maketable(&receiver);
    auto rand = makeRandSource(prng);

    for (u32 i = 0; i < msg.size(); i += 4)
    {
        auto min = std::min<u32>(4, msg.size() - i);

        for (u32 j = 0; j < min; j++)
            cs[j] = choices[i + j];

        receiver_rsgen(&receiver, Rs_pack, cs, rand);
        chl.asyncSendCopy(Rs_pack, sizeof(Rs_pack));
        receiver_keygen(&receiver, keys);

        for (u32 j = 0; j < min; j++)
            memcpy(&msg[i + j], keys[j], sizeof(block));
    }
}

void AsmSimplestOT::send(span<std::array<block, 2>> msg, PRNG& prng, Channel& chl)
{
    SENDER sender;

    u8 S_pack[SIMPLEST_OT_PACK_BYTES];
    u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
    u8 keys[2][4][SIMPLEST_OT_HASHBYTES];

    auto rand = makeRandSource(prng);
    sender_genS(&sender, S_pack, rand);
    chl.asyncSend(S_pack, sizeof(S_pack));

    for (u32 i = 0; i < msg.size(); i += 4)
    {
        chl.recv(Rs_pack, sizeof(Rs_pack));
        sender_keygen(&sender, Rs_pack, keys);

        auto min = std::min<u32>(4, msg.size() - i);
        for (u32 j = 0; j < min; j++)
        {
            memcpy(&msg[i + j][0], keys[0][j], sizeof(block));
            memcpy(&msg[i + j][1], keys[1][j], sizeof(block));
        }
    }
}

void AsmSimplestOT::sendSPack(SENDER& sender, span<std::array<block, 2>> msg, PRNG& prng, u8 S_pack[SIMPLEST_OT_PACK_BYTES])
{
    auto rand = makeRandSource(prng);
    sender_genS(&sender, S_pack, rand);
}

void AsmSimplestOT::sendMessage(SENDER& sender, span<std::array<block, 2>> msg, const u8* RS_pack_result)
{
    u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
    u8 keys[2][4][SIMPLEST_OT_HASHBYTES];

    for (u32 i = 0; i < msg.size(); i += 4)
    {
        memcpy(Rs_pack, RS_pack_result+i*sizeof(Rs_pack), sizeof(Rs_pack));
        sender_keygen(&sender, Rs_pack, keys);

        auto min = std::min<u32>(4, msg.size() - i);
        for (u32 j = 0; j < min; j++)
        {
            memcpy(&msg[i + j][0], keys[0][j], sizeof(block));
            memcpy(&msg[i + j][1], keys[1][j], sizeof(block));
        }
    }

}

void AsmSimplestOT::receiveSPack(RECEIVER& receiver, const BitVector& choices, span<block> msg, PRNG& prng, const u8 S_pack[SIMPLEST_OT_PACK_BYTES], u8* RS_pack_result)
{
    u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
    u8 keys[4][SIMPLEST_OT_HASHBYTES];
    u8 cs[4];

    memcpy(receiver.S_pack, S_pack, SIMPLEST_OT_PACK_BYTES);

    receiver_procS(&receiver);

    receiver_maketable(&receiver);
    auto rand = makeRandSource(prng);

    for (u32 i = 0; i < msg.size(); i += 4)
    {
        // u8 Rs_pack[4 * SIMPLEST_OT_PACK_BYTES];
        auto min = std::min<u32>(4, msg.size() - i);

        for (u32 j = 0; j < min; j++)
            cs[j] = choices[i + j];

        receiver_rsgen(&receiver, Rs_pack, cs, rand);
        // RS_pack_result[i] = Rs_pack;
        memcpy(RS_pack_result+i*sizeof(Rs_pack), Rs_pack, sizeof(Rs_pack));
        // RS_pack_result.push_back(Rs_pack);
        receiver_keygen(&receiver, keys);

        for (u32 j = 0; j < min; j++)
            memcpy(&msg[i + j], keys[j], sizeof(block));
    }
}

}  // namespace osuCrypto
#endif
