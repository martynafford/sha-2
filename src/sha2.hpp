// Copyright (c) 2018 Martyn Afford
// Licensed under the MIT licence

#ifndef SHA2_HPP
#define SHA2_HPP

#include <array>
#include <cstdint>
#include <cstring>

namespace sha2 {

template <size_t N>
using hash_array = std::array<uint8_t, N>;

using sha224_hash = hash_array<28>;
using sha256_hash = hash_array<32>;
using sha384_hash = hash_array<48>;
using sha512_hash = hash_array<64>;

// SHA-2 uses big-endian integers.
inline void
write_u32(uint8_t* dest, uint32_t x)
{
    *dest++ = (x >> 24) & 0xff;
    *dest++ = (x >> 16) & 0xff;
    *dest++ = (x >> 8) & 0xff;
    *dest++ = (x >> 0) & 0xff;
}

inline void
write_u64(uint8_t* dest, uint64_t x)
{
    *dest++ = (x >> 56) & 0xff;
    *dest++ = (x >> 48) & 0xff;
    *dest++ = (x >> 40) & 0xff;
    *dest++ = (x >> 32) & 0xff;
    *dest++ = (x >> 24) & 0xff;
    *dest++ = (x >> 16) & 0xff;
    *dest++ = (x >> 8) & 0xff;
    *dest++ = (x >> 0) & 0xff;
}

inline uint32_t
read_u32(const uint8_t* src)
{
    return static_cast<uint32_t>((src[0] << 24) | (src[1] << 16) |
                                 (src[2] << 8) | src[3]);
}

inline uint64_t
read_u64(const uint8_t* src)
{
    uint64_t upper = read_u32(src);
    uint64_t lower = read_u32(src + 4);
    return ((upper & 0xffffffff) << 32) | (lower & 0xffffffff);
}

// A compiler-recognised implementation of rotate right that avoids the
// undefined behaviour caused by shifting by the number of bits of the left-hand
// type. See John Regehr's article https://blog.regehr.org/archives/1063
inline uint32_t
ror(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (-n & 31));
}

inline uint64_t
ror(uint64_t x, uint64_t n)
{
    return (x >> n) | (x << (-n & 63));
}

// Utility function to truncate larger hashes. Assumes appropriate hash types
// (i.e., hash_array<N>) for type T.
template <typename T, size_t N>
inline T
truncate(const hash_array<N>& hash)
{
    T result;
    memcpy(result.data(), hash.data(), sizeof(result));
    return result;
}

// Both sha256_impl and sha512_impl are used by sha224/sha256 and
// sha384/sha512 respectively, avoiding duplication as only the initial hash
// values (s) and output hash length change.
inline sha256_hash
sha256_impl(const uint32_t* s, const uint8_t* data, uint64_t length)
{
    static_assert(sizeof(uint32_t) == 4, "sizeof(uint32_t) must be 4");
    static_assert(sizeof(uint64_t) == 8, "sizeof(uint64_t) must be 8");

    constexpr size_t chunk_bytes = 64;
    const uint64_t bit_length = length * 8;

    uint32_t hash[8] = {s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]};

    constexpr uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    auto chunk = [&hash, &k](const uint8_t* chunk_data) {
        uint32_t w[64] = {0};

        for (int i = 0; i != 16; ++i) {
            w[i] = read_u32(&chunk_data[i * 4]);
        }

        for (int i = 16; i != 64; ++i) {
            auto w15 = w[i - 15];
            auto w2 = w[i - 2];
            auto s0 = ror(w15, 7) ^ ror(w15, 18) ^ (w15 >> 3);
            auto s1 = ror(w2, 17) ^ ror(w2, 19) ^ (w2 >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        auto a = hash[0];
        auto b = hash[1];
        auto c = hash[2];
        auto d = hash[3];
        auto e = hash[4];
        auto f = hash[5];
        auto g = hash[6];
        auto h = hash[7];

        for (int i = 0; i != 64; ++i) {
            auto s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
            auto ch = (e & f) ^ (~e & g);
            auto temp1 = h + s1 + ch + k[i] + w[i];
            auto s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
            auto maj = (a & b) ^ (a & c) ^ (b & c);
            auto temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    };

    while (length >= chunk_bytes) {
        chunk(data);
        data += chunk_bytes;
        length -= chunk_bytes;
    }

    {
        std::array<uint8_t, chunk_bytes> buf;
        memcpy(buf.data(), data, length);

        auto i = length;
        buf[i++] = 0x80;

        if (i > chunk_bytes - 8) {
            while (i < chunk_bytes) {
                buf[i++] = 0;
            }

            chunk(buf.data());
            i = 0;
        }

        while (i < chunk_bytes - 8) {
            buf[i++] = 0;
        }

        write_u64(&buf[i], bit_length);

        chunk(buf.data());
    }

    sha256_hash result;

    for (uint8_t i = 0; i != 8; ++i) {
        write_u32(&result[i * 4], hash[i]);
    }

    return result;
}

inline sha512_hash
sha512_impl(const uint64_t* s, const uint8_t* data, uint64_t length)
{
    static_assert(sizeof(uint32_t) == 4, "sizeof(uint32_t) must be 4");
    static_assert(sizeof(uint64_t) == 8, "sizeof(uint64_t) must be 8");

    constexpr size_t chunk_bytes = 128;
    const uint64_t bit_length_low = length << 3;
    const uint64_t bit_length_high = length >> (64 - 3);

    uint64_t hash[8] = {s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]};

    constexpr uint64_t k[80] = {
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
        0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
        0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
        0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
        0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
        0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
        0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
        0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
        0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
        0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
        0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

    auto chunk = [&hash, &k](const uint8_t* chunk_data) {
        uint64_t w[80] = {0};

        for (int i = 0; i != 16; ++i) {
            w[i] = read_u64(&chunk_data[i * 8]);
        }

        for (int i = 16; i != 80; ++i) {
            auto w15 = w[i - 15];
            auto w2 = w[i - 2];
            auto s0 = ror(w15, 1) ^ ror(w15, 8) ^ (w15 >> 7);
            auto s1 = ror(w2, 19) ^ ror(w2, 61) ^ (w2 >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        auto a = hash[0];
        auto b = hash[1];
        auto c = hash[2];
        auto d = hash[3];
        auto e = hash[4];
        auto f = hash[5];
        auto g = hash[6];
        auto h = hash[7];

        for (int i = 0; i != 80; ++i) {
            auto s1 = ror(e, 14) ^ ror(e, 18) ^ ror(e, 41);
            auto ch = (e & f) ^ (~e & g);
            auto temp1 = h + s1 + ch + k[i] + w[i];
            auto s0 = ror(a, 28) ^ ror(a, 34) ^ ror(a, 39);
            auto maj = (a & b) ^ (a & c) ^ (b & c);
            auto temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    };

    while (length >= chunk_bytes) {
        chunk(data);
        data += chunk_bytes;
        length -= chunk_bytes;
    }

    {
        std::array<uint8_t, chunk_bytes> buf;
        memcpy(buf.data(), data, length);

        auto i = length;
        buf[i++] = 0x80;

        if (i > chunk_bytes - 16) {
            while (i < chunk_bytes) {
                buf[i++] = 0;
            }

            chunk(buf.data());
            i = 0;
        }

        while (i < chunk_bytes - 16) {
            buf[i++] = 0;
        }

        write_u64(&buf[i + 0], bit_length_high);
        write_u64(&buf[i + 8], bit_length_low);

        chunk(buf.data());
    }

    sha512_hash result;

    for (uint8_t i = 0; i != 8; ++i) {
        write_u64(&result[i * 8], hash[i]);
    }

    return result;
}

inline sha224_hash
sha224(const uint8_t* data, uint64_t length)
{
    // Second 32 bits of the fractional parts of the square roots of the ninth
    // through sixteenth primes 23..53
    const uint32_t initial_hash_values[8] = {0xc1059ed8,
                                             0x367cd507,
                                             0x3070dd17,
                                             0xf70e5939,
                                             0xffc00b31,
                                             0x68581511,
                                             0x64f98fa7,
                                             0xbefa4fa4};

    auto hash = sha256_impl(initial_hash_values, data, length);
    return truncate<sha224_hash>(hash);
}

inline sha256_hash
sha256(const uint8_t* data, uint64_t length)
{
    // First 32 bits of the fractional parts of the square roots of the first
    // eight primes 2..19:
    const uint32_t initial_hash_values[8] = {0x6a09e667,
                                             0xbb67ae85,
                                             0x3c6ef372,
                                             0xa54ff53a,
                                             0x510e527f,
                                             0x9b05688c,
                                             0x1f83d9ab,
                                             0x5be0cd19};

    return sha256_impl(initial_hash_values, data, length);
}

inline sha384_hash
sha384(const uint8_t* data, uint64_t length)
{
    const uint64_t initial_hash_values[8] = {0xcbbb9d5dc1059ed8,
                                             0x629a292a367cd507,
                                             0x9159015a3070dd17,
                                             0x152fecd8f70e5939,
                                             0x67332667ffc00b31,
                                             0x8eb44a8768581511,
                                             0xdb0c2e0d64f98fa7,
                                             0x47b5481dbefa4fa4};

    auto hash = sha512_impl(initial_hash_values, data, length);
    return truncate<sha384_hash>(hash);
}

inline sha512_hash
sha512(const uint8_t* data, uint64_t length)
{
    const uint64_t initial_hash_values[8] = {0x6a09e667f3bcc908,
                                             0xbb67ae8584caa73b,
                                             0x3c6ef372fe94f82b,
                                             0xa54ff53a5f1d36f1,
                                             0x510e527fade682d1,
                                             0x9b05688c2b3e6c1f,
                                             0x1f83d9abfb41bd6b,
                                             0x5be0cd19137e2179};

    return sha512_impl(initial_hash_values, data, length);
}

// SHA-512/t is a truncated version of SHA-512, where the result is truncated
// to t bits (in this implementation, t must be a multiple of eight). The two
// primariy variants of this are SHA-512/224 and SHA-512/256, both of which are
// provided through explicit functions (sha512_224 and sha512_256) below this
// function. On 64-bit platforms, SHA-512, and correspondingly SHA-512/t,
// should give a significant performance improvement over SHA-224 and SHA-256
// due to the doubled block size.
template <int bits>
inline hash_array<bits / 8>
sha512_t(const uint8_t* data, uint64_t length)
{
    static_assert(bits % 8 == 0, "Bits must be a multiple of 8 (i.e., bytes).");
    static_assert(0 < bits && bits <= 512, "Bits must be between 8 and 512");
    static_assert(bits != 384, "NIST explicitly denies 384 bits, use SHA-384.");

    const uint64_t modified_initial_hash_values[8] = {
        0x6a09e667f3bcc908 ^ 0xa5a5a5a5a5a5a5a5,
        0xbb67ae8584caa73b ^ 0xa5a5a5a5a5a5a5a5,
        0x3c6ef372fe94f82b ^ 0xa5a5a5a5a5a5a5a5,
        0xa54ff53a5f1d36f1 ^ 0xa5a5a5a5a5a5a5a5,
        0x510e527fade682d1 ^ 0xa5a5a5a5a5a5a5a5,
        0x9b05688c2b3e6c1f ^ 0xa5a5a5a5a5a5a5a5,
        0x1f83d9abfb41bd6b ^ 0xa5a5a5a5a5a5a5a5,
        0x5be0cd19137e2179 ^ 0xa5a5a5a5a5a5a5a5};

    // The SHA-512/t generation function uses a modified SHA-512 on the string
    // "SHA-512/t" where t is the number of bits. The modified SHA-512 operates
    // like the original but uses different initial hash values, as seen above.
    // The hash is then used for the initial hash values sent to the original
    // SHA-512. The sha512_224 and sha512_256 functions have this precalculated.
    constexpr int buf_size = 12;
    uint8_t buf[buf_size];

    auto buf_ptr = reinterpret_cast<char*>(buf);
    auto len = snprintf(buf_ptr, buf_size, "SHA-512/%d", bits);
    auto ulen = static_cast<uint64_t>(len);

    auto initial8 = sha512_impl(modified_initial_hash_values, buf, ulen);

    // To read the hash bytes back into 64-bit integers, we must convert back
    // from big-endian.
    uint64_t initial64[8];

    for (uint8_t i = 0; i != 8; ++i) {
        initial64[i] = read_u64(&initial8[i * 8]);
    }

    // Once the initial hash is computed, use regular SHA-512 and copy the
    // appropriate number of bytes.
    auto hash = sha512_impl(initial64, data, length);
    return truncate<hash_array<bits / 8>>(hash);
}

// It is preferable to use either sha512_224 or sha512_256 in place of
// sha512_t<224> or sha512_t<256> for better performance (as the initial
// hashes are precalculated), for slightly less syntactic noise and for
// consistency with the other functions.
inline sha224_hash
sha512_224(const uint8_t* data, uint64_t length)
{
    // Precalculated initial hash (The hash of "SHA-512/224" using the modified
    // SHA-512 generation function, described above in sha512_t).
    const uint64_t initial_hash_values[8] = {0x8c3d37c819544da2,
                                             0x73e1996689dcd4d6,
                                             0x1dfab7ae32ff9c82,
                                             0x679dd514582f9fcf,
                                             0x0f6d2b697bd44da8,
                                             0x77e36f7304c48942,
                                             0x3f9d85a86a1d36c8,
                                             0x1112e6ad91d692a1};

    auto hash = sha512_impl(initial_hash_values, data, length);
    return truncate<sha224_hash>(hash);
}

inline sha256_hash
sha512_256(const uint8_t* data, uint64_t length)
{
    // Precalculated initial hash (The hash of "SHA-512/256" using the modified
    // SHA-512 generation function, described above in sha512_t).
    const uint64_t initial_hash_values[8] = {0x22312194fc2bf72c,
                                             0x9f555fa3c84c64c2,
                                             0x2393b86b6f53b151,
                                             0x963877195940eabd,
                                             0x96283ee2a88effe3,
                                             0xbe5e1e2553863992,
                                             0x2b0199fc2c85b8aa,
                                             0x0eb72ddc81c52ca2};

    auto hash = sha512_impl(initial_hash_values, data, length);
    return truncate<sha256_hash>(hash);
}

} // sha2 namespace

#endif /* SHA2_HPP */
