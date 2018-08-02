// Copyright (c) 2018 Martyn Afford
// Licensed under the MIT licence

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include "sha2.hpp"

namespace {

template <typename T>
void
print_hash(char* buf, const T& hash)
{
    for (auto c : hash) {
        buf += sprintf(buf, "%02x", c);
    }
}

void
expect(const char* str,
       const char* expected224,
       const char* expected256,
       const char* expected384,
       const char* expected512,
       const char* expected512_224,
       const char* expected512_256)
{
    constexpr int max_hash_text_length = 129;
    char hash[max_hash_text_length] = {0};

    auto ptr = reinterpret_cast<const uint8_t*>(str);
    auto length = strlen(str);

    printf("source: \"%.100s\"%s", str, length > 100 ? "..." : "");
    printf(" [%zu bytes, %zu bits]\n", length, length * 8);

    print_hash(hash, sha2::sha224(ptr, length));
    printf("sha224: %s", hash);
    printf(" [%s]\n", strcmp(hash, expected224) == 0 ? "pass" : "FAIL");

    print_hash(hash, sha2::sha256(ptr, length));
    printf("sha256: %s", hash);
    printf(" [%s]\n", strcmp(hash, expected256) == 0 ? "pass" : "FAIL");

    print_hash(hash, sha2::sha384(ptr, length));
    printf("sha384: %s", hash);
    printf(" [%s]\n", strcmp(hash, expected384) == 0 ? "pass" : "FAIL");

    print_hash(hash, sha2::sha512(ptr, length));
    printf("sha512: %s", hash);
    printf(" [%s]\n", strcmp(hash, expected512) == 0 ? "pass" : "FAIL");

    print_hash(hash, sha2::sha512_224(ptr, length));
    printf("sha512/224: %s", hash);
    printf(" [%s]\n", strcmp(hash, expected512_224) == 0 ? "pass" : "FAIL");

    print_hash(hash, sha2::sha512_256(ptr, length));
    printf("sha512/256: %s", hash);
    printf(" [%s]\n", strcmp(hash, expected512_256) == 0 ? "pass" : "FAIL");

    // Test that sha512_t matches the corresponding sha512_224 and sha512_256
    auto sha512_t224 = sha2::sha512_t<224>(ptr, length);
    auto sha512_t256 = sha2::sha512_t<256>(ptr, length);
    auto sha512_224 = sha2::sha512_224(ptr, length);
    auto sha512_256 = sha2::sha512_256(ptr, length);

    if (sha512_t224 != sha512_224) {
        printf("FAIL: sha512_t<224> != sha512_224\n");

        print_hash(hash, sha512_t224);
        printf("sha512_t<224>: %s\n", hash);

        print_hash(hash, sha512_224);
        printf("sha512_224: %s\n", hash);
    }

    if (sha512_t256 != sha512_256) {
        printf("FAIL: sha512_t<256> != sha512_256\n");

        print_hash(hash, sha512_t256);
        printf("sha512_t<256>: %s\n", hash);

        print_hash(hash, sha512_256);
        printf("sha512_256: %s\n", hash);
    }

    putchar('\n');
}

} // anonymous namespace

int
main()
{
    // Tests based partly on NESSIE:
    // https://cosic.esat.kuleven.be/nessie/testvectors/hash/sha/index.html
    expect("",
           // sha224
           "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
           // sha256
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
           // sha384
           "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
           "274edebfe76f65fbd51ad2f14898b95b",
           // sha512
           "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
           "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
           // sha512/224
           "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
           // sha512/256
           "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");

    expect("a",
           // sha224
           "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
           // sha256
           "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
           // sha384
           "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e8517503"
           "3caa88e6d57bc35efae0b5afd3145f31",
           // sha512
           "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f53"
           "02860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
           // sha512/224
           "d5cdb9ccc769a5121d4175f2bfdd13d6310e0d3d361ea75d82108327",
           // sha512/256
           "455e518824bc0601f9fb858ff5c37d417d67c2f8e0df2babe4808858aea830f8");

    expect("abc",
           // sha224
           "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
           // sha256
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
           // sha384
           "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
           "8086072ba1e7cc2358baeca134c825a7",
           // sha512
           "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
           "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
           // sha512/224
           "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
           // sha512/256
           "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");

    expect("message digest",
           // sha224
           "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb",
           // sha256
           "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
           // sha384
           "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61"
           "dbd0d8b4de1390c256dcbb5d5fd99cd5",
           // sha512
           "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f33"
           "09e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
           // sha512/224
           "ad1a4db188fe57064f4f24609d2a83cd0afb9b398eb2fcaeaae2c564",
           // sha512/256
           "0cf471fd17ed69d990daf3433c89b16d63dec1bb9cb42a6094604ee5d7b4e9fb");

    expect("abcdefghijklmnopqrstuvwxyz",
           // sha224
           "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2",
           // sha256
           "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
           // sha384
           "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479f"
           "f2877f5f2936fa63bb43784b12f3ebb4",
           // sha512
           "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429"
           "955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
           // sha512/224
           "ff83148aa07ec30655c1b40aff86141c0215fe2a54f767d3f38743d8",
           // sha512/256
           "fc3189443f9c268f626aea08a756abe7b726b05f701cb08222312ccfd6710a26");

    expect("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
           // sha224
           "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
           // sha256
           "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
           // sha384
           "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6"
           "b0455a8520bc4e6f5fe95b1fe3c8452b",
           // sha512
           "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
           "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
           // sha512/224
           "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174",
           // sha512/256
           "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461");

    expect("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
           // sha224
           "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9",
           // sha256
           "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
           // sha384
           "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11"
           "a5341a6f41e0c202294736ed64db1a84",
           // sha512
           "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c4"
           "5c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
           // sha512/224
           "a8b4b9174b99ffc67d6f49be9981587b96441051e16e6dd036b140d3",
           // sha512/256
           "cdf1cc0effe26ecc0c13758f7b4a48e000615df241284185c39eb05d355bb9c8");

    expect(
        "1234567890123456789012345678901234567890"
        "1234567890123456789012345678901234567890",
        // sha224
        "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e",
        // sha256
        "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
        // sha384
        "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8f"
        "b0195996d2de9ca0df9d821ffee67026",
        // sha512
        "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a"
        "2354e093d76f3048b456764346900cb130d2a4fd5dd16abb5e30bcb850dee843",
        // sha512/224
        "ae988faaa47e401a45f704d1272d99702458fea2ddc6582827556dd2",
        // sha512/256
        "2c9fdbc0c90bdd87612ee8455474f9044850241dc105b1e8b94b8ddf5fac9148");

    std::vector<char> million(1000000, 'a');
    million.push_back(0);

    expect(million.data(),
           // sha224
           "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
           // sha256
           "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
           // sha384
           "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b"
           "07b8b3dc38ecc4ebae97ddd87f3d8985",
           // sha512
           "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
           "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
           // sha512/224
           "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287",
           // sha512/256
           "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21");

    return 0;
}
