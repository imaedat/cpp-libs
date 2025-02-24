#ifndef EVENT_ENGINE_HPP_
#define EVENT_ENGINE_HPP_

#include <assert.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#ifdef EVENT_ENGINE_VERBOSE
#    include <stdio.h>
#    include <sys/syscall.h>
#endif

#include <chrono>
#include <cstring>
#include <deque>
#include <list>
#include <mutex>
#include <system_error>
#include <unordered_set>

namespace tbd {

namespace detail {
inline void close(int& fd)
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

    bool oneshot() const noexcept
    {
        return oneshot_;
    }

    void set_oneshot(bool set = true) noexcept
    {
        oneshot_ = set;
    }

    virtual void top_half(bool)
    {
        // urgent work
    }

    virtual void bottom_half(bool)
    {
        // non-urgent, follow-up work
    }

  protected:
    int fd_ = -1;
    bool oneshot_ = false;

    event() noexcept = default;
    explicit event(bool oneshot) noexcept
        : oneshot_(oneshot)
    {}
};

class engine
{
  protected:
    struct timer_event
    {
        event* ev;
        int delta_ms;
    };

    class timer_list
    {
      public:
        int next_expiry()
        {
            return (!event_list_.empty()) ? event_list_.front().delta_ms : -1;
        }

        void add(event* ev, int timeout_ms)
        {
            update();

            if (timeout_ms <= 0) {
                return;
            }

            assert(!contains(ev));

            timer_event new_ev{ev, timeout_ms};

            auto it = event_list_.begin();
            for (; it != event_list_.end(); ++it) {
                if (new_ev.delta_ms < it->delta_ms) {
                    it->delta_ms -= new_ev.delta_ms;
                    break;
                }
                new_ev.delta_ms = std::max(new_ev.delta_ms - it->delta_ms, 1);
            }

            event_list_.insert(it, std::move(new_ev));
            event_set_.insert(ev);
            dump(__func__, ev);
        }

        void remove(event* ev)
        {
            remove_(ev);
            dump(__func__, ev);
        }

        event* pop()
        {
            assert(!event_list_.empty());
            auto* ev = event_list_.front().ev;
            remove_(ev);
            dump(__func__, ev);
            return ev;
        }

      private:
        std::list<timer_event> event_list_;
        std::unordered_set<event*> event_set_;
        std::chrono::steady_clock::time_point last_updated_;

        void remove_(event* ev) noexcept
        {
            update();

            if (event_list_.empty() || !contains(ev)) {
                return;
            }

            auto it = event_list_.begin();
            do {
                if (it->ev == ev) {
                    auto jt = std::next(it);
                    if (jt != event_list_.end()) {
                        jt->delta_ms += it->delta_ms;
                    }
                    break;
                }
            } while (++it != event_list_.end());

            assert(it != event_list_.end());
            event_list_.erase(it);
            event_set_.erase(ev);
        }

        void update() noexcept
        {
            using namespace std::chrono;
            auto now = steady_clock::now();
            auto elapsed = duration_cast<milliseconds>(now - last_updated_).count();
            last_updated_ = now;

            if (!event_list_.empty()) {
                auto over_elapsed = elapsed - event_list_.front().delta_ms;
                event_list_.front().delta_ms = std::max(event_list_.front().delta_ms - elapsed, 0L);

                auto it = event_list_.begin();
                while (over_elapsed > 0 && ++it != event_list_.end()) {
                    auto over_elapsed_left = it->delta_ms - over_elapsed;
                    if (over_elapsed_left >= 0) {
                        it->delta_ms = std::max(it->delta_ms - over_elapsed, 1L);
                        break;
                    }

                    it->delta_ms = 1;
                    over_elapsed = -over_elapsed_left;
                }
            }
        }

        bool contains(event* ev) const noexcept
        {
            return event_set_.find(ev) != event_set_.end();
        }

        void dump(const char* func, event* ev) const noexcept
        {
            (void)func;
            (void)ev;
#ifdef EVENT_ENGINE_VERBOSE
            bool omit = true;
            printf(" *** [%ld] %s(%d): {", syscall(SYS_gettid), func, ev->handle());
            int i = 0;
            long total = 0;
            for (const auto& te : event_list_) {
                if (!omit || i < 10) {
                    printf(" [%d] = { fd = %d, delta_ms = %d },", i, te.ev->handle(), te.delta_ms);
                }
                total += te.delta_ms;
                ++i;
            }
            auto len = event_list_.size();
            printf("%s } (len [%lu], total [%ld]) ***\n", ((omit && len > 10) ? " ..." : ""), len,
                   total);
#endif
        }
    };  // timer_list

    enum op
    {
        EV_ADD = 1,
        EV_DEL = 2,
        EV_TIM = 3,
    };

    struct event_request
    {
        enum op op;
        event* ev;
        int timeout_ms;
    };

    int epollfd_ = -1;
    int eventfd_ = -1;
    size_t nevents_ = 0;
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

    void register_event(event* ev, int timeout_ms = 0)
    {
        add_requestq(EV_ADD, ev, timeout_ms);
    }

    void register_timer(event* ev, int timeout_ms)
    {
        add_requestq(EV_TIM, ev, timeout_ms);
    }

    void deregister(event* ev)
    {
        add_requestq(EV_DEL, ev, 0);
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
            handle_timeout();
            return;
        }

        assert(nfds >= 1);
        for (auto i = 0; i < nfds; ++i) {
            if (eev[i].data.ptr == this) {
                handle_request();
            } else {
                handle_event(eev[i].data.ptr);
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
    void add_requestq(enum op op, event* ev, int timeout_ms)
    {
        static constexpr uint64_t one = 1;
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{op, ev, timeout_ms});
        auto nwritten = ::write(eventfd_, &one, sizeof(one));
        if (nwritten < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

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

        if (req.op == EV_ADD) {
            add_event(req.ev->handle(), req.ev, req.timeout_ms, req.ev->oneshot());
        } else if (req.op == EV_DEL) {
            delete_event(req.ev->handle(), req.ev);
        } else if (req.op == EV_TIM) {
            timerq_.add(req.ev, req.timeout_ms);
        } else {
            // ignore
        }
    }

    void add_event(int fd, void* ev, int timeout_ms = 0, bool oneshot = true)
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
        bool enoent = false;
        int ret = ::epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd, nullptr);
        if (ret < 0) {
            if (!(enoent = (errno == ENOENT))) {
                throw std::system_error(errno, std::generic_category());
            }
        }

        timerq_.remove((event*)ev);
        if (!enoent) {
            --nevents_;
        }
    }

    /**
     * event / timer callback
     */
    void handle_timeout()
    {
        auto* ev = timerq_.pop();
        if (ev->oneshot()) {
            delete_event(ev->handle(), ev);
        }
        ev->top_half(true);
        exec_bh(ev, true);
    }

    void handle_event(void* ptr)
    {
        auto* ev = (event*)ptr;
        if (ev->oneshot()) {
            delete_event(ev->handle(), ev);
        } else {
            timerq_.remove(ev);
        }

        ev->top_half(false);
        exec_bh(ev, false);
    }

    virtual void exec_bh(event* ev, bool timedout)
    {
        ev->bottom_half(timedout);
    }
};

}  // namespace tbd

#endif
