#define RATE_LIMITR_VERBOSE
#include "rate_limiter.hpp"

#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>

using namespace std;
using namespace std::chrono;
using namespace std::literals::chrono_literals;
using namespace tbd;

inline char* now()
{
    thread_local char buf[32] = {0};

    auto count = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
    auto sec = count / (1000 * 1000);
    auto usec = count % (1000 * 1000);
    struct tm tm;
    localtime_r(&sec, &tm);
    strftime(buf, 21, "%F %T.", &tm);
    sprintf(buf + 20, "%06ld", usec);
    return buf;
}

#define LOG(fmt, ...) printf("%s [%04ld] " fmt, now(), syscall(SYS_gettid), ##__VA_ARGS__)

static steady_clock::time_point start;
static unsigned long total = 0;

static void handler(int)
{
    auto elapsed = duration_cast<microseconds>(steady_clock::now() - start).count();
    auto rate = 1.0 * total * (1000 * 1000) / elapsed;
    printf("\nelapsed=%lu ms, total=%lu, %f per second\n", elapsed / 1000, total, rate);
    exit(0);
}

#define r(n) (random() % (n))

int main(int argc, char* argv[])
{
    signal(SIGINT, handler);

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

    start = steady_clock::now();
    while (true) {
        int count = 1 + r(3);
        auto waitms = r(300);
        bool ok = lim->try_request(count);
        LOG("req=%d, result=%s\n", count, (ok ? "success" : "denied"));
        if (ok) {
            total += count;
        }
        usleep(waitms * 1000);
    }
}
