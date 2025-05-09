#include "blake3_file.h"
#include <fstream>
#include <vector>
#include <mimalloc.h>
#include "blake3/blake3.h"
#include "literals.h"

static inline char hb2hex(unsigned char hb) {
    hb = hb & 0xF;
    return hb < 10 ? '0' + hb : hb - 10 + 'a';
}

constexpr auto BLOCK_SIZE = 200_MiB;
std::string blake3_file(const std::filesystem::path& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        return "";
    }

    auto size = std::filesystem::file_size(filename);
    if (size == 0) {
        return "";
    }

    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    char* buffer = nullptr;
    if (size <= BLOCK_SIZE) {
        buffer = (char*)mi_malloc(size);
        if (!buffer) {
            throw std::bad_alloc();
        }
        file.read(buffer, size);
        blake3_hasher_update(&hasher, buffer, size);
    }
    else {
        buffer = (char*)mi_malloc(BLOCK_SIZE);
        if (!buffer) {
            throw std::bad_alloc();
        }
        while (file.read(buffer, BLOCK_SIZE) || file.gcount() > 0) {
            blake3_hasher_update(&hasher, buffer, file.gcount());
        }
    }
    mi_free(buffer);
    file.close();

    uint8_t output[BLAKE3_OUT_LEN];
    blake3_hasher_finalize(&hasher, output, BLAKE3_OUT_LEN);

    std::string hash_hex;
    hash_hex.reserve(BLAKE3_OUT_LEN * 2);
    for (size_t i = 0; i < BLAKE3_OUT_LEN; ++i) {
        hash_hex.push_back(hb2hex(output[i] >> 4));
        hash_hex.push_back(hb2hex(output[i]));
    }

    return hash_hex;
}
