#include "resolver.hpp"

#include <stdio.h>

#include <chrono>

using namespace tbd;

void show_result(const char* host, int64_t addr)
{
    if (addr >= 0) {
        uint8_t* a = (uint8_t*)&addr;
        printf("host = %s,\taddr = %d.%d.%d.%d\n", host, a[0], a[1], a[2], a[3]);
    } else if (addr == -EAGAIN) {
        puts("timed out");
    } else if (addr == -ENOENT) {
        puts("no such node name");
    } else {
        puts("unknown error");
    }
}

template <typename R, typename F>
R stop_watch(F&& fn)
{
    using namespace std::chrono;
    auto t1 = steady_clock::now();
    R result = fn();
    auto t2 = steady_clock::now();
    fprintf(stderr, " elapsed = %ld us\n", duration_cast<microseconds>(t2 - t1).count());
    return result;
}

void same_host(const char* host)
{
    {
        puts("\n--- loop ---");
        resolver res(host);
        show_result(host, stop_watch<int64_t>([&] {
                        int64_t i, addr;
                        for (i = 0, addr = -1; addr < 0 && addr != -ENOENT; ++i) {
                            addr = res.lookup_nb();
                        }
                        printf("iters = %ld\n", i);
                        return addr;
                    }));
    }

    {
        puts("\n--- normal ---");
        resolver res(host);
        show_result(host, stop_watch<int64_t>([&] { return res.lookup(100); }));
    }

    {
        puts("\n--- signal ---");
        resolver_sig res(host);
        show_result(host, stop_watch<int64_t>([&] { return res.lookup(100); }));
    }

    {
        puts("\n--- thread --");
        resolver_thr res(host);
        show_result(host, stop_watch<int64_t>([&] { return res.lookup(100); }));
    }
}

int main(int argc, char* argv[])
{
    const char* host = "www.google.com";
    if (argc >= 2) {
        host = argv[1];
    }

    puts("\n=== same host ===");
    same_host(host);

    puts("\n=== diff host ===");
    {
        puts("\n--- loop ---");
        host = "www1.hatena.com";
        resolver res(host);
        show_result(host, stop_watch<int64_t>([&] {
                        int64_t i, addr;
                        for (i = 0, addr = -1; addr < 0 && addr != -ENOENT; ++i) {
                            addr = res.lookup_nb();
                        }
                        printf("iters = %ld\n", i);
                        return addr;
                    }));
    }

    {
        puts("\n--- normal ---");
        host = "www2.hatena.com";
        resolver res(host);
        show_result(host, stop_watch<int64_t>([&] { return res.lookup(100); }));
    }

    {
        puts("\n--- signal ---");
        host = "www3.hatena.com";
        resolver_sig res(host);
        show_result(host, stop_watch<int64_t>([&] { return res.lookup(100); }));
    }

    {
        puts("\n--- thread --");
        host = "www4.hatena.com";
        resolver_thr res(host);
        show_result(host, stop_watch<int64_t>([&] { return res.lookup(100); }));
    }

    return 0;
}
