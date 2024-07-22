#ifndef MESSAGE_QUEUE_HPP_
#define MESSAGE_QUEUE_HPP_

#include <errno.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <chrono>
#include <mutex>
#include <optional>
#include <queue>

namespace tbd {

template <typename T>
class message_queue
{
  public:
    message_queue() : eventfd_(eventfd(0, EFD_SEMAPHORE))
    {
        if (eventfd_ < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "message_queue: eventfd");
        }
    }

    ~message_queue()
    {
        close(eventfd_);
        eventfd_ = -1;
    }

    int poll_handle() const noexcept
    {
        return eventfd_;
    }

    void push(const T& msg)
    {
        std::lock_guard<std::mutex> lk(queue_mtx_);
        mq_.push(msg);
        write(eventfd_, &one, sizeof(one));
    }

    void push(T&& msg)
    {
        std::lock_guard<std::mutex> lk(queue_mtx_);
        mq_.push(std::forward<T>(msg));
        write(eventfd_, &one, sizeof(one));
    }

    T pop()
    {
#ifdef MESSAGE_QUEUE_TIMEDPOP_MULTIPLE_READERS
        std::lock_guard<std::timed_mutex> lk(reader_mtx_);
#endif

        return pop_internal();
    }

    std::optional<T> timed_pop(int wait_ms)
    {
        using namespace std::chrono;

#ifdef MESSAGE_QUEUE_TIMEDPOP_MULTIPLE_READERS
        auto t1 = steady_clock::now();
        std::unique_lock<std::timed_mutex> lk(reader_mtx_, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::milliseconds(wait_ms))) {
            return std::nullopt;
        }
        auto t2 = steady_clock::now();
        auto elapsed = duration_cast<milliseconds>(t2 - t1).count();
        if (elapsed > 0) {
            wait_ms -= elapsed;
        }
#endif

        struct pollfd fds;
        fds.fd = eventfd_;
        fds.events = POLLIN | POLLPRI | POLLRDHUP;
        fds.revents = 0;
        int nfds = poll(&fds, 1, wait_ms);
        if (nfds < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "message_queue::timed_pop: poll");
        }

        if (nfds > 0) {
            return pop_internal();
        } else {
            return std::nullopt;
        }
    }

  private:
    inline static constexpr uint64_t one = 1;

    int eventfd_ = -1;
    std::queue<T> mq_;
    std::mutex queue_mtx_;
#ifdef MESSAGE_QUEUE_TIMEDPOP_MULTIPLE_READERS
    std::timed_mutex reader_mtx_;
#endif

    T pop_internal()
    {
        uint64_t u;
        read(eventfd_, &u, sizeof(u));

        std::lock_guard<std::mutex> lk(queue_mtx_);
        T msg = std::move(mq_.front());
        mq_.pop();
        return msg;
    }
};

}  // namespace tbd

#endif
