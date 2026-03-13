#include "mutex_wrap.hpp"

#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>

#define THREAD_POOL_ENABLE_WAIT_ALL
#include "logger.hpp"
#include "thread_pool.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

logger con("mutex_wrap", "/dev/stdout");

void normal_mutex(thread_pool& pool)
{
    mutex_wrap str(string("hello"));

    {
        for (int i = 0; i < 10; ++i) {
            pool.submit([&, i] {
                con.info("task-%02d: start", i);
                auto ms = random() % 300;
                str.lock([&](auto& data) {
                    con.info("task-%02d: acquire resource(%s), work for %lu ms ...", i,
                             data.c_str(), ms);
                    usleep(ms * 1000);
                    con.info("task-%02d: finished", i);
                });
            });
        }

        pool.wait_all();
    }

    puts("---");
    {
        auto g = str.lock();
        printf("%s\n", g->c_str());
    }

    puts("---");
    {
        unique_lock lk(str.native_mutex());
        condition_variable cv;
        cv.wait_for(lk, milliseconds(500));
    }
}

#define is_writer(i) (((i) % 4 == 0))

void readwrite_mutex(thread_pool& pool)
{
    rwlock_wrap str(string("world"));

    {
        for (int i = 0; i < 10; ++i) {
            pool.submit([&, i] {
                con.info("task-%02d: start", i);
                auto ms = random() % 800;
                if (is_writer(i)) {
                    auto s = str.lock();
                    con.info("task-%02d: acquire write lock(%s), work for %lu ms ...", i,
                             s->c_str(), ms);
                    usleep(ms * 1000);
                    con.info("task-%02d: release write lock", i);
                    // s->clear();  // compile ok
                } else {
                    auto s = str.lock_shared();
                    con.info("task-%02d: acquire read lock(%s), work for %lu ms ...", i, s->c_str(),
                             ms);
                    usleep(ms * 1000);
                    con.info("task-%02d: release read lock", i);
                    // s->clear();  // compile error
                }
            });
        }

        pool.wait_all();
    }

    puts("---");
    {
        auto g = str.lock_shared();
        printf("%s\n", (*g).c_str());
    }
}

int main()
{
    srandom(time(nullptr));

    thread_pool pool;

    normal_mutex(pool);
    puts("===");
    readwrite_mutex(pool);
}
