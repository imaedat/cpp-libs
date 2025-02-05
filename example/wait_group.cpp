#include "wait_group.hpp"

#include <unistd.h>

#include "thread_pool.hpp"

using namespace tbd;

#define NWORKERS 4
#define NTASKS 16

int main()
{
    srandom(time(nullptr));

    wait_group wg;
    thread_pool pool(NWORKERS);

    for (auto i = 0; i < NTASKS; ++i) {
        wg.add();
        pool.submit([i, &wg] {
            auto t = random() % (1000 * 1000);
            printf("task-%02d: work for %lu ms ...\n", i, t);
            usleep(t);
            printf("task-%02d: done\n", i);
            wg.done();
        });
    }

    wg.wait();
}
