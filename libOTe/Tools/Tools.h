#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all
// copyright. No restrictions are placed on its use.

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/MatrixView.h>
#include <string>
#include <vector>
#include "cryptoTools/Common/Matrix.h"
namespace osuCrypto
{
static inline void mul128(block x, block y, block& xy1, block& xy2)
{
    x.gf128Mul(y, xy1, xy2);
}


static inline void mul190(block a0, block a1, block b0, block b1, block& c0, block& c1, block& c2)
{
    // c3c2c1c0 = a1a0 * b1b0
    block c4, c5;

    mul128(a0, b0, c0, c1);
    // mul128(a1, b1, c2, c3);
    a0 = (a0 ^ a1);
    b0 = (b0 ^ b1);
    mul128(a0, b0, c4, c5);
    c4 = (c4 ^ c0);
    c4 = (c4 ^ c2);
    c5 = (c5 ^ c1);
    // c5 = _mm_xor_si128(c5, c3);
    c1 = (c1 ^ c4);
    c2 = (c2 ^ c5);
}

static inline void mul256(
    block a0, block a1, block b0, block b1, block& c0, block& c1, block& c2, block& c3)
{
    block c4, c5;
    mul128(a0, b0, c0, c1);
    mul128(a1, b1, c2, c3);
    a0 = (a0 ^ a1);
    b0 = (b0 ^ b1);
    mul128(a0, b0, c4, c5);
    c4 = (c4 ^ c0);
    c4 = (c4 ^ c2);
    c5 = (c5 ^ c1);
    c5 = (c5 ^ c3);
    c1 = (c1 ^ c4);
    c2 = (c2 ^ c5);
}
//{
//    // c3c2c1c0 = a1a0 * b1b0
//    block c4, c5;

//    mul128(a0, b0, c0, c1);
//    mul128(a1, b1, c2, c3);
//    a0 = _mm_xor_si128(a0, a1);
//    b0 = _mm_xor_si128(b0, b1);
//    mul128(a0, b0, c4, c5);
//    c4 = _mm_xor_si128(c4, c0);
//    c4 = _mm_xor_si128(c4, c2);
//    c5 = _mm_xor_si128(c5, c1);
//    c5 = _mm_xor_si128(c5, c3);
//    c1 = _mm_xor_si128(c1, c4);
//    c2 = _mm_xor_si128(c2, c5);
//}


void print(std::array<block, 128>& inOut);
u8 getBit(std::array<block, 128>& inOut, u64 i, u64 j);

void eklundh_transpose128(std::array<block, 128>& inOut);
void eklundh_transpose128x1024(std::array<std::array<block, 8>, 128>& inOut);

#ifdef OC_ENABLE_SSE2
void sse_transpose128(std::array<block, 128>& inOut);
void sse_transpose128x1024(std::array<std::array<block, 8>, 128>& inOut);
#endif
void transpose(const MatrixView<block>& in, const MatrixView<block>& out);
void transpose(const MatrixView<u8>& in, const MatrixView<u8>& out);
std::vector<block> stringToBlockVec(const std::string& string);
std::string blockVecToString(const std::vector<block>& blockVec);
std::string EncBlockVecToString(const std::vector<block>& blockVec);
block ToBlock(const std::vector<u64>& array);
std::vector<u64> ToU64Vector(const std::vector<block>& blockArray);
std::vector<block> ToBlockVector(const std::vector<u64>& array);
std::vector<u64> ToU64Vector(const block& block);
std::vector<u64> MatrixToU64Vector(const Matrix<block>& matrix);
Matrix<block> U64VectorToMatrix(const std::vector<u64>& array, u64 rows, u64 cols);
// block bytesArrayToBlock(std::vector<u8>& array);
// std::vector<u8> blockToBytesArray(const block& block);


inline void transpose128(std::array<block, 128>& inOut)
{
#ifdef OC_ENABLE_SSE2
    sse_transpose128(inOut);
#else
    eklundh_transpose128(inOut);
#endif
}


inline void transpose128x1024(std::array<std::array<block, 8>, 128>& inOut)
{
#ifdef OC_ENABLE_SSE2
    sse_transpose128x1024(inOut);
#else
    eklundh_transpose128x1024(inOut);
#endif
}


}  // namespace osuCrypto
