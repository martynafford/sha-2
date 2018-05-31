# SHA-2 cryptographic hash functions

This is a header-only, C++11 implementation of the
[SHA-2 cryptographic hash functions](https://en.wikipedia.org/wiki/SHA-2)
(see disclaimer below) as put forward in NIST's
[FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) and
the C example code in [RFC 6234](https://tools.ietf.org/html/rfc6234).

*Note*, this code is designed to run on little-endian systems only.

## Integration

The single header file, `sha2.hpp` is in the `src` directory. Integration is
simply including the header,

```c++
#include "sha2.hpp"
```

in the relevant files. C++11 or later must be enabled (e.g., `-std=c++11`,
`-std=c++14`, `-std=c++17` or `-std=c++2a`  for GCC and Clang).

## Example

A simple example of hashing an ASCII string follows,

```c++
int main()
{
    const char* const text = "abc";

    auto ptr = reinterpret_cast<const uint8_t*>(text);
    auto hash = sha2::sha512(ptr, strlen(text));

    // Print the hash
    for (auto c : hash) {
        printf("%02x", c);
    }
}
```

An example use can be found in main.cpp, which prints out test hashes.

## Reference

Everything is within the `sha2` namespace.

### Types

Each hash is a typedef for a byte array of the appropriate size:

```c++
using sha224_hash = std::array<uint8_t, 28>;
using sha256_hash = std::array<uint8_t, 32>;
using sha384_hash = std::array<uint8_t, 48>;
using sha512_hash = std::array<uint8_t, 64>;
```

### Functions

Each function takes a pointer to some data and a length while returning the
corresponding hash. These functions are designed for simplicity and so hash
everything at once. There is no streaming solution; the hashing cannot be
resumed.

```c++
sha224_hash sha224(const uint8_t* data, uint64_t length);
sha256_hash sha256(const uint8_t* data, uint64_t length);
sha384_hash sha384(const uint8_t* data, uint64_t length);
sha512_hash sha512(const uint8_t* data, uint64_t length);
```

## Disclaimer

While the code is based on the RFC and tests show that the hashes match what is
expected, this code should not be considered production ready. Do not use this,
without further vetting, in security contexts. It was written for educational
purposes, primarily for myself but hopefully others too. Performance was not a
primary concern.

## Licence

<img align="right" src="http://opensource.org/trademarks/opensource/OSI-Approved-License-100x137.png">

Licensed under the [MIT Licence](http://opensource.org/licenses/MIT):

Copyright &copy; 2018 [Martyn Afford](https://mafford.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

