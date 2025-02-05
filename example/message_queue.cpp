#define MESSAGE_QUEUE_MULTIPLE_READERS
#include "message_queue.hpp"

#include <atomic>

#include "thread_pool.hpp"
#include "wait_group.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

#define msleep(ms) this_thread::sleep_for(milliseconds((ms)))

struct non_copyable
{
    int id;
    explicit non_copyable(int n)
        : id(n)
    {}
    non_copyable(const non_copyable&) = delete;
    non_copyable& operator=(const non_copyable&) = delete;
    non_copyable(non_copyable&&) = default;
    non_copyable& operator=(non_copyable&&) = default;
};

int main()
{
    constexpr size_t NWRITER = 16;
    constexpr size_t NREADER = 4;

    message_queue<non_copyable> mq;

    thread_pool tpool(NWRITER + NREADER);

    srandom(time(nullptr));

    wait_group rwg(NREADER);
    atomic<bool> remains{true};
    for (size_t i = 0; i < NREADER; ++i) {
        tpool.submit([i, &mq, &remains, &rwg] {
            // printf("reader-%02lu: start\n", i);

            while (remains) {
                auto m = mq.timed_pop(100);
                if (m) {
                    printf("reader-%02lu: pop %d\n", i, m->id);
                } else {
                    // printf("reader-%02lu: ... timed out\n", i);
                }
            }
            // printf("reader-%02lu: done\n", i);
            rwg.done();
        });
    }

    wait_group wwg(NWRITER);
    for (size_t i = 0; i < NWRITER; ++i) {
        tpool.submit([i, &mq, &wwg] {
            auto ms = 1 + random() % 600;
            printf("writer-%02lu: wait %ld ms ...\n", i, ms);
            msleep(ms);
            non_copyable nc(i);
            mq.push(move(nc));
            // printf("writer-%02lu: done\n", i);
            wwg.done();
        });
    }

    wwg.wait();
    puts("--- all writers done ---");
    remains = false;
    rwg.wait();
    puts("--- all readers done ---");

    return 0;
}
