#include "uuid.hpp"

#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <iostream>

using namespace std;
using namespace std::chrono;
using namespace tbd;

#define DEFENV(var, init) static int var = (init)
// clang-format off
#define GETENV(var) if (auto *p = ::getenv(#var); p) { var = ::atoi(p); }
#define DUMP(id)                                                               \
    cout << #id << ": " << (id) << ", time = " << time2str((id).time_point())  \
         << ", hash = " << hash<uuid>{}((id)) << "\n"
// clang-format on

DEFENV(V, 7);
DEFENV(N, 20);

#pragma GCC diagnostic ignored "-Wformat-truncation"
string time2str(system_clock::time_point tp)
{
    auto sec = floor<seconds>(tp);
    auto ns = duration_cast<nanoseconds>(tp - sec).count();
    auto t = system_clock::to_time_t(sec);
    struct tm tm = {};
    ::localtime_r(&t, &tm);
    char buf[32] = {0};
    ::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%09ld", tm.tm_year + 1900,
               tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ns);
    return buf;
}

int main()
{
    {
        uuid id0;
        assert(id0.nil());

        auto id1 = uuid::v7();
        ::usleep(1);
        auto id2 = uuid::v7();
        assert(id1 < id2);
        DUMP(id1);
        DUMP(id2);

        auto id3 = uuid::from_string(id1.to_string());
        assert(id3 == id1);
        DUMP(id3);

        uint8_t buf[16] = {0};
        id1.write_to(buf);
        auto id4 = uuid::from_bytes(buf);
        assert(id4 == id3);
        DUMP(id4);
        cout << "\n";

        // static helper
        uuid::util::generate_v7(buf);
        auto s = uuid::util::to_string(buf);
        uint8_t buf2[16] = {0};
        uuid::util::parse(s, buf2);
        assert(memcmp(buf, buf2, 16) == 0);
    }

    GETENV(V);
    GETENV(N);
    uuid (*gen)() = (V == 4) ? uuid::v4 : uuid::v7;
    auto n = N;
    auto s = steady_clock::now();
    while (n-- > 0) {
#if 1
        auto id = gen();
        cout << id;
        if (id.version() == 7) {
            cout << " (time = " << time2str(id.time_point()) << ")";
        }
        cout << "\n";
#else
        [[maybe_unused]] auto _ = gen();
#endif
    }
    auto e = duration_cast<microseconds>(steady_clock::now() - s).count();
    cout << "\ntotal " << N << ", elapsed = " << e << " us, avg = " << (1.0 * e / N) << " us"
         << endl;
}
