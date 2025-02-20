#ifndef EVENT_ENGINE_HPP_
#define EVENT_ENGINE_HPP_

#include <assert.h>
#include <sys/epoll.h>
#include <unistd.h>
// v2
#include <sys/eventfd.h>
#include <sys/timerfd.h>
// XXX
#include <stdio.h>

#include <cstring>
#include <system_error>
// v2
#include <bitset>
#include <deque>
#include <list>
#include <mutex>
#include <unordered_map>

namespace tbd {

namespace detail {
void close(int& fd)
{
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}
}  // namespace detail

class engine;
class event
{
  public:
    event(const event&) = delete;
    event& operator=(const event&) = delete;
    event(event&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    event& operator=(event&& rhs) noexcept
    {
        using std::swap;
        if (this != &rhs) {
            swap(fd_, rhs.fd_);
            swap(engine_, rhs.engine_);
        }
        return *this;
    }

    virtual ~event()
    {
        detail::close(fd_);
    }

    int handle() const noexcept
    {
        return fd_;
    }

    virtual void top_half(int, bool)
    {
        // urgent work
    }

    virtual void bottom_half(int, bool)
    {
        // non-urgent, follow-up work
    }

  protected:
    int fd_ = -1;
    engine* engine_ = nullptr;

    event(engine& eng)
        : engine_(&eng)
    {}
};

class engine
{
  protected:
    enum op
    {
        EV_ADD = 1,
        EV_DEL = 2,
    };

    struct event_request
    {
        event *ev;
        long timeout_ms;
        enum op op;
    };

    struct timer_expiry
    {
        int fd;
        long timeout_ms;
        long delta_ms;
    };

    int epollfd_ = -1;
    int timerfd_ = -1;
    int eventfd_ = -1;

    std::mutex mtx_;
    std::deque<event_request> requestq_;
    std::unordered_map<int, void*> fd_events_;

    std::list<timer_expiry> timerq_;
    std::bitset<4096> in_timerq_;

  public:
    engine()
    {
        epollfd_ = ::epoll_create1(0);
        if (epollfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        timerfd_ = ::timerfd_create(CLOCK_MONOTONIC, 0);
        if (timerfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        eventfd_ = ::eventfd(0, EFD_SEMAPHORE);
        if (eventfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        add_event(timerfd_, this, 0, false);
        add_event(eventfd_, this, 0, false);
        in_timerq_.reset();
    }

    virtual ~engine()
    {
        detail::close(epollfd_);
        detail::close(eventfd_);
        detail::close(timerfd_);
    }

    void register_event(event *ev, long timeout_ms = 0)
    {
        static constexpr uint64_t one = 1;
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{ev, timeout_ms, EV_ADD});
        auto nwritten = ::write(eventfd_, &one, sizeof(one));
        if (nwritten < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    void deregister_event(event *ev)
    {
        static constexpr uint64_t one = 1;
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{ev, 0, EV_DEL});
        auto nwritten = ::write(eventfd_, &one, sizeof(one));
        if (nwritten < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    void run_next()
    {
        auto nwatch = fd_events_.size();
        struct epoll_event eev[nwatch];
        ::memset(eev, 0, sizeof(struct epoll_event) * nwatch);
        int nfds = ::epoll_wait(epollfd_, eev, nwatch, -1);
        if (nfds < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        assert(nfds != 0);

        for (auto i = 0; i < nfds; ++i) {
            int source = eev[i].data.fd;
            if (source == timerfd_) {
                timer_expired();
            } else if (source == eventfd_) {
                handle_request();
            } else {
                handle_event(source, false);
            }
        }
    }

    void run_loop()
    {
        while (true) {
            run_next();
        }
    }

  protected:
    //
    // add new / delete existing event
    //
    void handle_request()
    {
        std::unique_lock<decltype(mtx_)> lk(mtx_);
        auto req = std::move(requestq_.front());
        requestq_.pop_front();
        uint64_t one;
        auto nread = ::read(eventfd_, &one, sizeof(one));
        if (nread < 0) {
            throw std::system_error(errno, std::generic_category());
        }
        lk.unlock();

        if (req.op == EV_ADD) {
            add_event(req.ev->handle(), req.ev, req.timeout_ms);
        } else if (req.op == EV_DEL) {
            delete_event(req.ev->handle());
        } else {
            // ignore
        }
    }

    void add_event(int fd, void* ev, long timeout_ms, bool oneshot = true)
    {
        struct epoll_event eev;
        ::memset(&eev, 0, sizeof(eev));
        eev.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | (oneshot ? EPOLLONESHOT : 0U);
        eev.data.fd = fd;
        int op = (fd_events_.find(fd) == fd_events_.end()) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
        int ret = ::epoll_ctl(epollfd_, op, fd, &eev);
        if (ret < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        add_timerq(fd, timeout_ms);
        fd_events_.emplace(fd, ev);
    }

    void delete_event(int fd)
    {
        int ret = ::epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd, nullptr);
        if (ret < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        remove_timerq(fd);
        fd_events_.erase(fd);
    }

    //
    // event callback
    //
    void handle_event(int fd, bool timedout = false)
    {
        remove_timerq(fd);

        auto* ev = (event*)fd_events_.at(fd);
        ev->top_half(ev->handle(), timedout);
        exec_bh(ev, timedout);
    }

    virtual void exec_bh(event* ev, bool timedout)
    {
        ev->bottom_half(ev->handle(), timedout);
    }

    //
    // timer list
    //
    void dump_timerq(const char *func, int fd)
    {
        (void)func;
        (void)fd;
#if 1
        printf("%s(%d): {", func, fd);
        int i = 0;
        for (const auto& te : timerq_) {
            printf("[%d] = { fd = %d, delta_ms = %ld }, ", i++, te.fd, te.delta_ms);
        }
        printf("}\n");
#endif
    }

#define DUMP_TIMERQ(fd) dump_timerq(__func__, (fd))

    void add_timerq(int fd, long timeout_ms)
    {
        if (timeout_ms <= 0) {
            return;
        }

        assert(!in_timerq_.test(fd));

        in_timerq_.set(fd);
        timer_expiry new_expiry{fd, timeout_ms, timeout_ms};

        if (timerq_.empty()) {
            timerq_.push_back(std::move(new_expiry));
            timer_set(timeout_ms);
            DUMP_TIMERQ(fd);
            return;
        }

        auto it = timerq_.begin();
        it->delta_ms = timer_left_ms();
        if (timeout_ms < it->delta_ms) {
            // insert to head, and update timer
            it->delta_ms -= timeout_ms;
            timer_set(timeout_ms);
        } else {
            do {
                new_expiry.delta_ms = std::max(new_expiry.delta_ms - it->delta_ms, 1L);
            } while (++it != timerq_.end() && new_expiry.delta_ms >= it->delta_ms);
        }

        timerq_.insert(it, std::move(new_expiry));
        DUMP_TIMERQ(fd);
    }

    void remove_timerq(int fd)
    {
        if (timerq_.empty() || !in_timerq_.test(fd)) {
            return;
        }

        auto it = timerq_.begin();
        if (it->fd == fd) {
            // remove head, and update timer
            auto jt = std::next(it);
            if (jt != timerq_.end()) {
                jt->delta_ms += timer_left_ms();
                timer_set(jt->delta_ms);
            } else {
                // timer clear
                timer_set(0);
            }
            timerq_.erase(it);
        } else {
            while (++it != timerq_.end()) {
                if (it->fd == fd) {
                    auto jt = std::next(it);
                    if (jt != timerq_.end()) {
                        jt->delta_ms += it->delta_ms;
                    }
                    timerq_.erase(it);
                    break;
                }
            }
        }

        in_timerq_.reset(fd);
        DUMP_TIMERQ(fd);
    }

    //
    // timer
    //
    void timer_expired()
    {
        assert(!timerq_.empty());

        uint64_t counter;
        auto nread = ::read(eventfd_, &counter, sizeof(counter));
        if (nread < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        auto expired = std::move(timerq_.front());
        timerq_.pop_front();

        if (!timerq_.empty()) {
            timer_set(timerq_.front().delta_ms);
        }

        handle_event(expired.fd, true);
        DUMP_TIMERQ(-1);
    }

    void timer_set(long timeout_ms)
    {
        static constexpr long ns_scale = 1000 * 1000 * 1000;

        auto nsec = timeout_ms * 1000 * 1000;
        long sec = 0;
        if (nsec >= ns_scale) {
            sec = nsec / ns_scale;
            nsec %= ns_scale;
        }
        // clang-format off
        struct itimerspec t{{0, 0}, {sec, nsec}};
        // clang-format on
        if (::timerfd_settime(timerfd_, 0, &t, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    long timer_left_ms()
    {
        // clang-format off
        struct itimerspec t{{0, 0}, {0, 0}};
        // clang-format on
        if (::timerfd_gettime(timerfd_, &t) < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        return (t.it_value.tv_sec * 1000) + (t.it_value.tv_nsec / (1000 * 1000));
    }
};

namespace v1 {
class engine;
class event
{
  public:
    event(const event&) = delete;
    event& operator=(const event&) = delete;
    event(event&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    event& operator=(event&& rhs) noexcept
    {
        using std::swap;
        if (this != &rhs) {
            swap(fd_, rhs.fd_);
            swap(engine_, rhs.engine_);
        }
        return *this;
    }

    virtual ~event()
    {
        detail::close(fd_);
    }

    int handle() const noexcept
    {
        return fd_;
    }

    virtual void top_half(int)
    {
        // urgent work
    }

    virtual void bottom_half(int)
    {
        // non-urgent, follow-up work
    }

  protected:
    int fd_ = -1;
    engine* engine_ = nullptr;

    event(engine& eng)
        : engine_(&eng)
    {}
};

class engine
{
  public:
    engine()
        : epollfd_(::epoll_create1(0))
    {
        if (epollfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    virtual ~engine()
    {
        detail::close(epollfd_);
    }

    void register_event(int fd, event* ev, bool oneshot = true)
    {
        struct epoll_event eev;
        ::memset(&eev, 0, sizeof(eev));
        eev.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | (oneshot ? EPOLLONESHOT : 0U);
        eev.data.ptr = ev;
        int op = EPOLL_CTL_ADD;
    again:
        int ret = ::epoll_ctl(epollfd_, op, fd, &eev);
        if (ret < 0) {
            if (errno == EEXIST) {
                op = EPOLL_CTL_MOD;
                goto again;
            }
            throw std::system_error(errno, std::generic_category());
        }
    }

    void deregister_event(int fd)
    {
        int ret = ::epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd, nullptr);
        if (ret < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    void run_one(int wait_ms = -1)
    {
        struct epoll_event eev;
        ::memset(&eev, 0, sizeof(eev));
        int nfds = ::epoll_wait(epollfd_, &eev, 1, wait_ms);
        if (nfds < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        if (nfds == 0) {
            return;
        }

        assert(nfds == 1);
        auto* ev = (event*)eev.data.ptr;
        ev->top_half(ev->handle());

        exec_bh(ev);
    }

    void run_loop()
    {
        while (true) {
            run_one();
        }
    }

  protected:
    int epollfd_ = -1;

    virtual void exec_bh(event* ev)
    {
        ev->bottom_half(ev->handle());
    }
};
}  // namespace v1

}  // namespace tbd

#endif
