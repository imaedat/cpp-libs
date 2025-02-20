#ifndef EVENT_ENGINE_HPP_
#define EVENT_ENGINE_HPP_

#include <assert.h>
#include <sys/epoll.h>
#include <unistd.h>
// v2
#include <sys/eventfd.h>
// XXX
#include <stdio.h>

#include <cstring>
#include <system_error>
// v2
#include <chrono>
#include <deque>
#include <list>
#include <mutex>
#include <unordered_set>

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

    event() = default;
};

class engine
{
  protected:
    struct timer_entry
    {
        event* ev;
        long timeout_ms;
        long delta_ms;
    };

    class timer_list
    {
      public:
        long next_expiry() const noexcept
        {
            return (!timerq_.empty()) ? timerq_.front().delta_ms : -1;
        }

        void add(event* ev, long timeout_ms)
        {
            update();

            if (timeout_ms <= 0) {
                return;
            }

            assert(!contains(ev));

            in_timerq_.insert(ev);
            timer_entry entry{ev, timeout_ms, timeout_ms};

            if (timerq_.empty()) {
                timerq_.push_back(std::move(entry));
                dump(__func__, ev);
                return;
            }

            auto it = timerq_.begin();
            if (timeout_ms < it->delta_ms) {
                // insert to head
                it->delta_ms -= timeout_ms;
            } else {
                do {
                    entry.delta_ms = std::max(entry.delta_ms - it->delta_ms, 1L);
                } while (++it != timerq_.end() && entry.delta_ms >= it->delta_ms);
            }

            timerq_.insert(it, std::move(entry));
            dump(__func__, ev);
        }

        void remove(event* ev)
        {
            update();

            if (timerq_.empty() || !contains(ev)) {
                return;
            }

            auto it = timerq_.begin();
            if (it->ev == ev) {
                // remove head, jt becomes head
                auto jt = std::next(it);
                if (jt != timerq_.end()) {
                    jt->delta_ms += until_expire_sv_;
                }
                timerq_.erase(it);
            } else {
                while (++it != timerq_.end()) {
                    if (it->ev == ev) {
                        auto jt = std::next(it);
                        if (jt != timerq_.end()) {
                            jt->delta_ms += it->delta_ms;
                        }
                        timerq_.erase(it);
                        break;
                    }
                }
            }

            in_timerq_.erase(ev);
            dump(__func__, ev);
        }

        event* expired()
        {
            update();

            assert(!timerq_.empty());

            auto expired = std::move(timerq_.front());
            timerq_.pop_front();
            in_timerq_.erase(expired.ev);

            dump(__func__, expired.ev);

            return expired.ev;
        }

      private:
        std::list<timer_entry> timerq_;
        std::unordered_set<event*> in_timerq_;
        std::chrono::steady_clock::time_point last_updated_;

        std::chrono::steady_clock::time_point now_sv_;
        long until_expire_sv_;

        void update() noexcept
        {
            using namespace std::chrono;
            now_sv_ = steady_clock::now();

            if (!timerq_.empty()) {
                until_expire_sv_ = timerq_.front().delta_ms -
                                   duration_cast<milliseconds>(now_sv_ - last_updated_).count();
                timerq_.front().delta_ms = until_expire_sv_;
            }

            last_updated_ = now_sv_;
        }

        bool contains(event* ev) const noexcept
        {
            return in_timerq_.find(ev) != in_timerq_.end();
        }

        void dump(const char* func, event* ev)
        {
            (void)func;
            (void)ev;
#if 1
            printf(" *** %s(%d): {", func, ev->handle());
            int i = 0;
            for (const auto& te : timerq_) {
                printf(" [%d] = { fd = %d, delta_ms = %ld },", i++, te.ev->handle(), te.delta_ms);
            }
            printf(" }\n");
#endif
        }
    };

    enum op
    {
        EV_ADD = 1,
        EV_DEL = 2,
    };

    struct event_request
    {
        event* ev;
        long timeout_ms;
        enum op op;
    };

    int epollfd_ = -1;
    int eventfd_ = -1;
    int nevents_ = 0;

    std::mutex mtx_;
    std::deque<event_request> requestq_;
    timer_list timerq_;

  public:
    engine()
    {
        epollfd_ = ::epoll_create1(0);
        if (epollfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        eventfd_ = ::eventfd(0, EFD_SEMAPHORE);
        if (eventfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        add_event(eventfd_, this, 0, false);
    }

    virtual ~engine()
    {
        detail::close(epollfd_);
        detail::close(eventfd_);
    }

    void register_event(event* ev, long timeout_ms = 0)
    {
        static constexpr uint64_t one = 1;
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{ev, timeout_ms, EV_ADD});
        auto nwritten = ::write(eventfd_, &one, sizeof(one));
        if (nwritten < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    void deregister_event(event* ev)
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
        struct epoll_event eev[nevents_];
        ::memset(eev, 0, sizeof(struct epoll_event) * nevents_);
        int nfds = ::epoll_wait(epollfd_, eev, nevents_, timerq_.next_expiry());
        if (nfds < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        if (nfds == 0) {
            handle_event(timerq_.expired(), true);
            return;
        }

        assert(nfds >= 1);
        for (auto i = 0; i < nfds; ++i) {
            if (eev[i].data.ptr == this) {
                handle_request();
            } else {
                handle_event(eev[i].data.ptr, false);
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
    /**
     * add new / delete existing event
     */
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
            delete_event(req.ev->handle(), req.ev);
        } else {
            // ignore
        }
    }

    void add_event(int fd, void* ev, long timeout_ms, bool oneshot = true)
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

        timerq_.add((event*)ev, timeout_ms);
        if (op == EPOLL_CTL_ADD) {
            ++nevents_;
        }
    }

    void delete_event(int fd, void* ev)
    {
        int ret = ::epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd, nullptr);
        if (ret < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        timerq_.remove((event*)ev);
        --nevents_;
    }

    /**
     * event / timer callback
     */
    void handle_event(void* ptr, bool timedout = false)
    {
        auto* ev = (event*)ptr;

        if (!timedout) {
            timerq_.remove(ev);
        }

        ev->top_half(ev->handle(), timedout);
        exec_bh(ev, timedout);
    }

    virtual void exec_bh(event* ev, bool timedout)
    {
        ev->bottom_half(ev->handle(), timedout);
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
