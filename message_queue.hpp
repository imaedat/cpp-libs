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

#include <type_traits>

namespace tbd {

template <typename T>
class message_queue
{
  public:
    message_queue()
        : eventfd_(::eventfd(0, EFD_SEMAPHORE))
        , queue_mtx_(std::make_unique<typename std::decay<decltype(*queue_mtx_)>::type>())
#ifdef MESSAGE_QUEUE_TIMEDPOP_MULTIPLE_READERS
        , reader_mtx_(std::make_unique<typename std::decay<decltype(*reader_mtx_)>::type>())
#endif
    {
        if (eventfd_ < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "message_queue: eventfd");
        }
    }

    message_queue(const message_queue&) = delete;
    message_queue& operator=(const message_queue&) = delete;
    message_queue(message_queue&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    message_queue& operator=(message_queue&& rhs) noexcept
    {
        using std::swap;
        if (this != &rhs) {
            swap(eventfd_, rhs.eventfd_);
            swap(mq_, rhs.mq_);
            swap(queue_mtx_, rhs.queue_mtx_);
#ifdef MESSAGE_QUEUE_TIMEDPOP_MULTIPLE_READERS
            swap(reader_mtx_, rhs.reader_mtx_);
#endif
        }
        return *this;
    }

    ~message_queue()
    {
        if (eventfd_ >= 0) {
            ::close(eventfd_);
            eventfd_ = -1;
        }
    }

    int poll_handle() const noexcept
    {
        return eventfd_;
    }

    void push(const T& msg)
    {
        std::lock_guard<decltype(*queue_mtx_)> lk(*queue_mtx_);
        mq_.push(msg);
        (void)::write(eventfd_, &one, sizeof(one));
    }

    void push(T&& msg)
    {
        std::lock_guard<decltype(*queue_mtx_)> lk(*queue_mtx_);
        mq_.push(std::forward<T>(msg));
        (void)::write(eventfd_, &one, sizeof(one));
    }

    T pop()
    {
#ifdef MESSAGE_QUEUE_TIMEDPOP_MULTIPLE_READERS
        std::lock_guard<decltype(*reader_mtx_)> lk(*reader_mtx_);
#endif

        return pop_internal();
    }

    std::optional<T> timed_pop(int wait_ms)
    {
        using namespace std::chrono;

#ifdef MESSAGE_QUEUE_TIMEDPOP_MULTIPLE_READERS
        auto t1 = steady_clock::now();
        std::unique_lock<decltype(*reader_mtx_)> lk(*reader_mtx_, std::defer_lock);
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
        int nfds = ::poll(&fds, 1, wait_ms);
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
    std::unique_ptr<std::mutex> queue_mtx_;
#ifdef MESSAGE_QUEUE_TIMEDPOP_MULTIPLE_READERS
    std::unique_ptr<std::timed_mutex> reader_mtx_;
#endif

    T pop_internal()
    {
        uint64_t u;
        (void)::read(eventfd_, &u, sizeof(u));

        std::lock_guard<decltype(*queue_mtx_)> lk(*queue_mtx_);
        T msg = std::move(mq_.front());
        mq_.pop();
        return msg;
    }
};

}  // namespace tbd

#endif
