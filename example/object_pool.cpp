#include "object_pool.hpp"

#include <chrono>
#include <cstdlib>
#include <thread>

#include "thread_pool.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

#define msleep(ms) this_thread::sleep_for(milliseconds((ms)))

static inline uint64_t utime()
{
    auto count = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
    return count % (1000 * 1000);
}

static int id = 0;

struct S
{
    int data;
};

int main()
{
    constexpr int nobjs = 3;
    constexpr int nworkers = 12;

    object_pool<S> opool(nobjs, [] { return new S{++id}; });
    thread_pool tpool(nworkers);

    srandom(time(nullptr));

    for (unsigned i = 0; i < nworkers; ++i) {
        tpool.submit([&opool, i] {
            printf("%06lu [%02d] start\n", utime(), i);
            auto obj = (i % 2) ? opool.acquire(1400) : opool.acquire_shared(1400);
            if (obj) {
                auto ms = 200 + random() % 800;
                printf("%06lu [%02d] acquire %d, and work for %ld ms ...\n", utime(), i, obj->data,
                       ms);
                msleep(ms);
                printf("%06lu [%02d] release %d\n", utime(), i, obj->data);
            } else {
                printf("%06lu [%02d] cannot acquired\n", utime(), i);
            }
        });
    }

    return 0;
}
