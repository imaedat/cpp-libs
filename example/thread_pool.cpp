#define THREAD_POOL_ENABLE_WAIT_ALL
#include "thread_pool.hpp"

#include <unistd.h>

using namespace tbd;

#define NWORKERS 4
#define NTASKS 16

int main()
{
    srandom(time(nullptr));

    thread_pool pool(NWORKERS);

    for (auto i = 0; i < NTASKS; ++i) {
        pool.submit([i] {
            auto t = random() % (1000 * 1000);
            printf("task-%02d: work for %lu ms ...\n", i, t);
            usleep(t);
            printf("task-%02d: done\n", i);
        });
    }

    pool.wait_all();
}
