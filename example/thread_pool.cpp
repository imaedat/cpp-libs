#define THREAD_POOL_ENABLE_WAIT_ALL
#define THREAD_POOL_ENABLE_DYNAMIC_RESIZE
#define THREAD_POOL_IDLE_KEEP_ALIVE_SEC 1
#include "thread_pool.hpp"

#include <unistd.h>

#include "logger.hpp"

using namespace tbd;

#define NWORKERS 4
#define NTASKS 20

int main()
{
    srandom(time(nullptr));

    logger logger("thrpool", "/dev/stdout");
    thread_pool pool(NWORKERS);

    for (auto i = 0; i < NTASKS; ++i) {
        pool.submit([&, i] {
            auto t = 100 + random() % (3 * 1000 * 1000);
            logger.info("task-%02d: work for %lu ms ...", i, t);
            usleep(t);
            logger.info("task-%02d: done", i);
        });
        usleep(100);
    }

    pool.wait_all();
}
