#ifndef MESSAGE_QUEUE_HPP_
#define MESSAGE_QUEUE_HPP_

#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>

namespace tbd {

namespace detail {
class defer_block
{
  public:
    explicit defer_block(std::function<void()>&& fn)
        : fn_(std::forward<std::function<void()>>(fn))
    {}

    ~defer_block()
    {
        try {
            fn_();
        } catch (...) {
            // ignore
        }
    }

  private:
    std::function<void()> fn_;
};
}  // namespace detail

template <typename T>
class message_queue
{
  public:
    message_queue()
        : eventfd_(eventfd(0, EFD_SEMAPHORE))
    {
        if (eventfd_ < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "message_queue: eventfd");
        }
    }

    ~message_queue()
    {
        close_(eventfd_);
        eventfd_ = -1;
    }

    int poll_handle() const
    {
        return eventfd_;
    }

    void push(const T& msg)
    {
        std::lock_guard<std::mutex> lk(queue_mtx_);
        mq_.push(msg);
        ::write(eventfd_, &one, sizeof(one));
    }

    void push(T&& msg)
    {
        std::lock_guard<std::mutex> lk(queue_mtx_);
        mq_.push(std::forward<T>(msg));
        ::write(eventfd_, &one, sizeof(one));
    }

    T pop()
    {
        uint64_t u;
        ::read(eventfd_, &u, sizeof(u));

        std::lock_guard<std::mutex> lk(queue_mtx_);
        T msg = std::move(mq_.front());
        mq_.pop();
        return msg;
    }

    std::optional<T> timed_pop(int wait_ms)
    {
        int epollfd = -1;
        detail::defer_block d([epollfd] { close_(epollfd); });

        epollfd = epoll_create1(0);
        if (epollfd < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "message_queue::timed_pop: epoll_create1");
        }

        struct epoll_event ev;
        ev.events = EPOLLIN;
        int ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, eventfd_, &ev);
        if (ret < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "message_queue::timed_pop: epoll_ctl");
        }

#ifdef MESSAGE_QUEUE_TIMEDPOP_MULTIPLE_READERS
        std::unique_lock<std::timed_mutex> lk(reader_mtx_, std::defer_lock);
        if (!lk.try_lock_for(std::chrono::milliseconds(wait_ms))) {
            return std::nullopt;
        }
#endif

        int nfds = epoll_wait(epollfd, &ev, 1, wait_ms);
        if (nfds < 0) {
            throw std::system_error(errno, std::generic_category(),
                    "message_queue::timed_pop: epoll_wait");
        }

        if (nfds > 0) {
            return pop();
        } else {
            return std::nullopt;
        }
    }

  private:
    inline static constexpr uint64_t one = 1;
    static void close_(int fd)
    {
        if (fd >= 0) {
            ::close(fd);
        }
    }

    int eventfd_ = -1;
    std::queue<T> mq_;
    std::mutex queue_mtx_;
#ifdef MESSAGE_QUEUE_TIMEDPOP_MULTIPLE_READERS
    std::timed_mutex reader_mtx_;
#endif
};

}  // namespace tbd

#endif
