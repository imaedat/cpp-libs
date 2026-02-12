#define RATE_LIMITER_VERBOSE
#include "rate_limiter.hpp"

#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>

#include "util.h"

using namespace std;
using namespace std::chrono;
using namespace std::literals::chrono_literals;
using namespace tbd;

static steady_clock::time_point start_;
static unsigned long total_ = 0;

static void handler(int)
{
    auto elapsed = duration_cast<microseconds>(steady_clock::now() - start_).count();
    auto rate = 1.0 * total_ * (1000 * 1000) / elapsed;
    printf("\nelapsed=%lu ms, total=%lu, %f per second\n", elapsed / 1000, total_, rate);
    exit(0);
}

#define r(n) (random() % (n))

#define WAIT_IN_REQUEST

int main(int argc, char* argv[])
{
    signal(SIGINT, handler);
    signal(SIGTERM, handler);

    srandom(time(nullptr));

    auto limit = 10;
    auto window = 1s;
    unique_ptr<rate_limiter> lim;
    if (argc > 1) {
        if (argv[1][0] == '1') {
            lim = make_unique<token_bucket>(limit, window);
        } else if (argv[1][0] == '2') {
            lim = make_unique<sliding_window_log>(limit, window);
        }
    }
    if (!lim) {
        lim = make_unique<sliding_window_counter>(limit, window);
    }

    start_ = steady_clock::now();
    while (true) {
        int count = 1 + r(4);
        [[maybe_unused]] auto waitms = r(300);
        auto t1 = steady_clock::now();
        bool ok = true;
#ifdef WAIT_IN_REQUEST
        lim->request(count);
#else
        std::tie(ok, std::ignore) = lim->try_request(count);
#endif
        auto t2 = steady_clock::now();
        LOG("req=%d, result=%s, time=%ld us\n", count, (ok ? "success" : "denied"),
            duration_cast<microseconds>(t2 - t1).count());
        if (ok) {
            total_ += count;
        }
#ifndef WAIT_IN_REQUEST
        usleep(waitms * 1000);
#endif
    }
}
