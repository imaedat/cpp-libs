#include "mutex_wrap.hpp"

#include <unistd.h>

#include "thread_pool.hpp"

using namespace std;
using namespace tbd;

int main()
{
    srandom(time(nullptr));

    // mutex_wrap<string> str("hello");
    mutex_wrap str(string("hello"));

    thread_pool pool;

    for (int i = 0; i < 10; ++i) {
        pool.submit([&, i] {
            printf("task-%02d: start\n", i);
            auto guard = str.lock();
            auto ms = random() % 1000;
            printf("task-%02d: acquire resource(%s), work for %lu ms ...\n", i, guard->c_str(), ms);
            usleep(ms * 1000);
            printf("task-%02d: finished\n", i);
        });
    }
}
