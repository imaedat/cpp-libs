#include "mutex_wrap.hpp"

#include <unistd.h>

#include <chrono>

#define THREAD_POOL_ENABLE_WAIT_ALL
#include "thread_pool.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

void normal_mutex(thread_pool& pool)
{
    // mutex_wrap<string> str("hello");
    mutex_wrap str(string("hello"));

    for (int i = 0; i < 10; ++i) {
        pool.submit([&, i] {
            printf("task-%02d: start\n", i);
            auto guard = str.lock();
            auto ms = random() % 300;
            printf("task-%02d: acquire resource(%s), work for %lu ms ...\n", i, guard->c_str(), ms);
            usleep(ms * 1000);
            printf("task-%02d: finished\n", i);
        });
    }

    pool.wait_all();

    unique_lock lk(*str);
    condition_variable cv;
    cv.wait_for(lk, milliseconds(2000));
}

#define is_writer(i) (((i) % 4 == 0))

void readwrite_mutex(thread_pool& pool)
{
    rwlock_wrap str(string("world"));

    for (int i = 0; i < 10; ++i) {
        pool.submit([&, i] {
            printf("task-%02d: start\n", i);
            auto guard = is_writer(i) ? str.lock() : str.lock_shared();
            auto ms = random() % 800;
            printf("task-%02d: acquire for %s(%s), work for %lu ms ...\n", i,
                   (is_writer(i) ? "write" : "read "), guard->c_str(), ms);
            usleep(ms * 1000);
            printf("task-%02d: finished\n", i);
        });
    }

    pool.wait_all();
}

int main()
{
    srandom(time(nullptr));

    thread_pool pool;

    normal_mutex(pool);
    puts("---");
    readwrite_mutex(pool);
}
