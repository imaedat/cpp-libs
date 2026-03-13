// #define WAIT_GROUP_WITH_SEMAPHORE
#include "semaphore.hpp"

#include <unistd.h>

#include <thread>

#define THREAD_POOL_ENABLE_WAIT_ALL
#include "logger.hpp"
#include "thread_pool.hpp"

using namespace std;
using namespace tbd;

logger con("semaphore", "/dev/stdout");

void semaphore_sample()
{
    unsigned nworkers = 3 + random() % 4;
    printf("-- semaphore_sample (nworkers = %u, nsem = 2) --\n", nworkers);

    semaphore sem(2);
    thread_pool pool(nworkers);

    for (auto i = 0U; i < nworkers; ++i) {
        pool.submit([&, i] {
            auto work_us = 1 + random() % (1000 * 1000);
            sem.acquire();
            con.info("worker-%02u: acquire semaphore, work for %ld us ...", i, work_us);
            usleep(work_us);
            con.info("worker-%02u: release semaphore, work done", i);
            sem.release();
        });
    }

    pool.wait_all();

    puts("");
}

void parker_sample()
{
    unsigned niters = 1 + random() % 4;
    printf("-- parker_sample (niters = %u) --\n", niters);

    parker p1, p2;

    thread thr([&] {
        for (auto i = 0U; i < niters; ++i) {
            p2.park();
            puts("     <-- pong");
            p1.unpark();
        }
    });

    p1.unpark();
    for (auto i = 0U; i < niters; ++i) {
        p1.park();
        puts("ping -->");
        p2.unpark();
    }

    p1.park();
    thr.join();

    puts("");
}

void wait_group_sample()
{
    unsigned nworkers = 2 + random() % 4;
    unsigned ntasks = 10 + random() % 6;
    printf("-- wait_group_sample (nworkers = %u, ntasks = %u) --\n", nworkers, ntasks);

    wait_group wg;
    thread_pool pool(nworkers);

    for (auto i = 0U; i < ntasks; ++i) {
        wg.add();
        pool.submit([i, &wg] {
            auto work_us = 1 + random() % (1000 * 1000);
            con.info("task-%02u: work for %lu us ...", i, work_us);
            usleep(work_us);
            con.info("task-%02u: done", i);
            wg.done();
        });
    }

    wg.wait();

    puts("");
}

int main()
{
    srandom(time(nullptr));

    semaphore_sample();

    parker_sample();

    wait_group_sample();

    return 0;
}
