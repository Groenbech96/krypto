# krypto
Cryptography algorithms written in C++20

## Current Algorithms
* AES 128, 194, 256 symmetic key encryption. Implementation specification: <https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf>



## AES
* Padding: ANSI X9.23, PKCS#7
* Modes: ECB, CBC

#### Implementation notes

The input is padded, so no need to give an exact multiple of 16 byte input.  

Any sequential container that adhere to the contiguous_iterator concept can be passed as key, plain text and cipher text. 

#### Examples 

```c++

#include "krypto/aes.h"
...

std::array<unsigned char, 32> key = { 0x00, 0x01, ..., 0x1f };
krypto::aes<256, krypto::modes::ecb, krypto::pad::pkcs7> aes(key);

// input data
std::vector<unsigned char> plain_text = { some data };

// encrypt / decrypt 
const auto cipher = aes.encrypt(plain_text);
const auto plain_text = aes.decrypt(cipher);

```
