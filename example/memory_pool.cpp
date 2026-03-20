#include "memory_pool.hpp"

#include <stdlib.h>
#include <unistd.h>

#include <chrono>

#include "logger.hpp"
#define THREAD_POOL_ENABLE_WAIT_ALL
#include "thread_pool.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

void with_mutex()
{
    // aligns up to 256B
    memory_pool pool(250, 120);
    vector<void*> borders;
    logger logger("with_mutex", "/dev/stdout");

    for (size_t i = 0; i < 121; ++i) {
        auto* p = pool.acquire();
        if (i < 4 || (60 < i && i < 69) || 116 < i) {
            logger.info("[%03lu] addr=%p", i, p);
        } else if (i == 4 || i == 116) {
            logger.info("---");
        }
        if (60 < i && i < 69) {
            borders.push_back(p);
        }
    }

    for (const auto& p : borders) {
        pool.release(p);
    }

    logger.info("===");

    for (size_t i = 0; i < 8; ++i) {
        auto* p = pool.acquire();
        logger.info("[%03lu] addr=%p", i, p);
    }
}

void with_lockfree()
{
    size_t nworkers = 16;
    memory_pool_lf mpool(250, 4);
    thread_pool tpool(8);
    logger logger("with_lockfree", "/dev/stdout");
    // logger.set_level("debug");

    {
        auto mp2 = move(mpool);
        memory_pool_lf mp3(1, 1);
        mp3 = move(mp2);
        mpool = move(mp3);
    }

    for (size_t i = 0; i < nworkers; ++i) {
        tpool.submit([i, &mpool, &logger] {
            int r = 0;
            auto t = random() % (1000 * 1000);
        again:
            auto* p = mpool.acquire();
            if (!p) {
                logger.debug("worker-%02lu: cannot acquired, retry (%d)", i, ++r);
                usleep(10 * 1000);
                goto again;
            }
            logger.info("worker-%02lu: acquired %p, work for %lu ms ...", i, p, t);
            usleep(t);
            logger.info("worker-%02lu: release  %p", i, p);
            mpool.release(p);
        });
    }
    tpool.wait_all();
}

void bench()
{
    constexpr size_t THREADS = 8;
    constexpr size_t ITERS = 10000;
    constexpr size_t BLOCKSZ = 4096;
    constexpr size_t COUNT = 7;  // 8
    constexpr unsigned WORK_US = 0;

    thread_pool thrpool(THREADS);

    {
        memory_pool pool(BLOCKSZ, COUNT);
        auto t = steady_clock::now();
        for (size_t i = 0; i < THREADS; ++i) {
            thrpool.submit([&pool] {
                for (size_t j = 0; j < ITERS; ++j) {
                    auto* p = pool.acquire();
                    if (WORK_US > 0) {
                        usleep(WORK_US);
                    }
                    pool.release(p);
                }
            });
        }

        thrpool.wait_all();
        printf("mt: elapsed %lu us\n",
               duration_cast<microseconds>(steady_clock::now() - t).count());
    }

    {
        atomic<size_t> retry{0};
        memory_pool_lf pool(BLOCKSZ, COUNT);
        auto t = steady_clock::now();
        for (size_t i = 0; i < THREADS; ++i) {
            thrpool.submit([&pool, &retry] {
                for (size_t j = 0; j < ITERS; ++j) {
                again:
                    auto* p = pool.acquire();
                    if (!p) {
                        retry.fetch_add(1, memory_order_relaxed);
                        this_thread::yield();
                        goto again;
                    }
                    if (WORK_US > 0) {
                        usleep(WORK_US);
                    }
                    pool.release(p);
                }
            });
        }

        thrpool.wait_all();
        printf("lf: elapsed %lu us (#retries = %lu)\n",
               duration_cast<microseconds>(steady_clock::now() - t).count(), retry.load());
    }
}

int main()
{
    srandom(time(nullptr));

    with_mutex();

    puts("---");

    with_lockfree();

    puts("---");

    bench();
}
