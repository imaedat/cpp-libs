#include "memory_pool.hpp"

#include <stdlib.h>
#include <unistd.h>

#define THREAD_POOL_ENABLE_WAIT_ALL
#include "thread_pool.hpp"

using namespace std;
using namespace tbd;

void with_mutex()
{
    // aligns up to 256B
    memory_pool pool(250, 120);
    vector<void*> borders;

    for (size_t i = 0; i < 121; ++i) {
        auto* p = pool.acquire();
        if (i < 4 || (60 < i && i < 69) || 116 < i) {
            printf("[%03lu] addr=%p\n", i, p);
        } else if (i == 4 || i == 116) {
            puts("---");
        }
        if (60 < i && i < 69) {
            borders.push_back(p);
        }
    }

    for (const auto& p : borders) {
        pool.release(p);
    }

    puts("===");

    for (size_t i = 0; i < 8; ++i) {
        auto* p = pool.acquire();
        printf("[%03lu] addr=%p\n", i, p);
    }
}

void with_lockfree()
{
    size_t nworkers = 16;
    memory_pool_lf mpool(250, 4);
    thread_pool tpool(8);

    for (size_t i = 0; i < nworkers; ++i) {
        tpool.submit([i, &mpool] {
            int r = 0;
            auto t = random() % (1000 * 1000);
        again:
            auto* p = mpool.acquire();
            if (!p) {
                printf("worker-%02lu: cannot acquired, retry (%d)\n", i, ++r);
                usleep(10 * 1000);
                // usleep(500 * 1000);
                goto again;
            }
            printf("worker-%02lu: acquired %p, work for %lu ms ...\n", i, p, t);
            usleep(t);
            printf("worker-%02lu: release  %p\n", i, p);
            mpool.release(p);
        });
    }
    tpool.wait_all();

    auto mp2 = std::move(mpool);
    memory_pool_lf mp3(1, 1);
    mp3 = std::move(mp2);
}

int main()
{
    srandom(time(nullptr));

    with_mutex();

    puts("---");

    with_lockfree();
}
