#define MESSAGE_QUEUE_MULTIPLE_READERS
#include "message_queue.hpp"

#include <unistd.h>

#include <atomic>

#include "logger.hpp"
#include "semaphore.hpp"
#include "thread_pool.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

struct non_copyable
{
    int id;
    explicit non_copyable(int n)
        : id(n)
    {
    }
    non_copyable(const non_copyable&) = delete;
    non_copyable& operator=(const non_copyable&) = delete;
    non_copyable(non_copyable&&) noexcept = default;
    non_copyable& operator=(non_copyable&&) noexcept = default;
};

int main()
{
    constexpr size_t NWRITER = 16;
    constexpr size_t NREADER = 4;

    message_queue<non_copyable> mq;

    logger logger("mesgq", "/dev/stdout");
    thread_pool thrpool(NWRITER + NREADER);

    srandom(time(nullptr));

    wait_group rwg(NREADER);
    atomic<bool> remains{true};
    for (size_t i = 0; i < NREADER; ++i) {
        thrpool.submit([i, &mq, &remains, &logger, &rwg] {
            // logger.info("reader-%02lu: start", i);

            while (remains) {
                auto m = mq.timed_pop(100);
                if (m) {
                    logger.info("reader-%02lu: pop %d", i, m->id);
                } else {
                    // logger.info("reader-%02lu: ... timed out", i);
                }
            }
            // logger.info("reader-%02lu: done", i);
            rwg.done();
        });
    }

    wait_group wwg(NWRITER);
    for (size_t i = 0; i < NWRITER; ++i) {
        thrpool.submit([i, &mq, &logger, &wwg] {
            auto ms = 1 + random() % 600;
            // logger.info("writer-%02lu: wait %ld ms ...", i, ms);
            usleep(ms * 1000);
            non_copyable nc(i);
            logger.info("writer-%02lu: push %lu", i, i);
            mq.push(move(nc));
            wwg.done();
        });
    }

    wwg.wait();
    logger.info("--- all writers done ---");
    remains = false;
    rwg.wait();
    logger.info("--- all readers done ---");

    return 0;
}
