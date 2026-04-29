#include "uuid.hpp"

#include <unistd.h>

#include <cassert>
#include <cstdlib>
#include <iostream>

#define DEFENV(var, init) static int var = (init)
// clang-format off
#define GETENV(var) if (auto *p = ::getenv(#var); p) { var = ::atoi(p); }
// clang-format on

using namespace std;
using namespace tbd;

DEFENV(V, 7);
DEFENV(N, 10);

int main()
{
    auto id1 = uuid::v7();
    ::usleep(100);
    auto id2 = uuid::v7();
    assert(id1 < id2);

    auto id3 = uuid::from_string(id1.to_string());
    assert(id3 == id1);

    uint8_t buf[16] = {0};
    id1.write_to(buf);
    auto id4 = uuid::from_bytes(buf);
    assert(id4 == id3);

    GETENV(V);
    GETENV(N);
    uuid (*gen)() = (V == 4) ? uuid::v4 : uuid::v7;
    while (N-- > 0) {
        cout << gen() << "\n";
    }
}
