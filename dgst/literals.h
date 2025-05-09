#pragma once

constexpr unsigned long long operator"" _GiB(unsigned long long n) {
    return n * 1024ULL * 1024ULL * 1024ULL;
}

constexpr unsigned long long operator"" _MiB(unsigned long long n) {
    return n * 1024ULL * 1024ULL;
}

constexpr unsigned long long operator"" _KiB(unsigned long long n) {
    return n * 1024ULL;
}
