#define RATE_LIMITR_VERBOSE
#include "rate_limiter.hpp"

#include <signal.h>
#include <unistd.h>

#include <chrono>
#include <string>

using namespace std;
using namespace std::chrono;
using namespace std::literals::chrono_literals;
using namespace tbd;

static string now()
{
    auto count = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
    auto sec = count / (1000 * 1000);
    auto usec = count % (1000 * 1000);
    struct tm tm;
    localtime_r(&sec, &tm);
    char buf[32] = {0}, result[64] = {0};
    strftime(buf, sizeof(buf), "%F %T", &tm);
    sprintf(result, "%s.%06ld", buf, usec);
    return result;
}

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

int main()
{
    signal(SIGINT, handler);

    srandom(time(nullptr));

    auto limit = 10;
    auto window = 1s;
    // token_bucket lim(limit, window);
    // sliding_window_log lim(limit, window);
    sliding_window_counter lim(limit, window);

    start = steady_clock::now();
    while (true) {
        int count = 1 + r(3);
        auto waitms = r(300);
        bool ok = lim.try_request(count);
        printf("%s req=%d, result=%s\n", now().c_str(), count, (ok ? "success" : "denied"));
        if (ok) {
            total += count;
        }
        usleep(waitms * 1000);
    }
}
