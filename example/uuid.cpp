#include "uuid.hpp"

#include <unistd.h>

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <iostream>

#define DEFENV(var, init) static int var = (init)
// clang-format off
#define GETENV(var) if (auto *p = ::getenv(#var); p) { var = ::atoi(p); }
// clang-format on

using namespace std;
using namespace std::chrono;
using namespace tbd;

DEFENV(V, 7);
DEFENV(N, 10);

int main()
{
    auto id1 = uuid::v7();
    ::usleep(1);
    auto id2 = uuid::v7();
    assert(id1 < id2);
    cout << "id1 = " << id1 << ", hash = " << hash<uuid>{}(id1) << "\n";
    cout << "id2 = " << id2 << ", hash = " << hash<uuid>{}(id2) << "\n";

    auto id3 = uuid::from_string(id1.to_string());
    assert(id3 == id1);
    cout << "id3 = " << id3 << ", hash = " << hash<uuid>{}(id3) << "\n";

    uint8_t buf[16] = {0};
    id1.write_to(buf);
    auto id4 = uuid::from_bytes(buf);
    assert(id4 == id3);
    cout << "id4 = " << id4 << ", hash = " << hash<uuid>{}(id4) << "\n\n";

    GETENV(V);
    GETENV(N);
    uuid (*gen)() = (V == 4) ? uuid::v4 : uuid::v7;
    auto n = N;
    auto s = steady_clock::now();
    while (n-- > 0) {
        cout << gen() << "\n";
        // [[maybe_unused]] auto _ = gen();
    }
    auto e = duration_cast<microseconds>(steady_clock::now() - s).count();
    cout << "\ncount " << N << " total elapsed = " << e << " us, avg = " << (1.0 * e / N) << " us"
         << endl;
}
