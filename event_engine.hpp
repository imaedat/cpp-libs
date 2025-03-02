#ifndef EVENT_ENGINE_HPP_
#define EVENT_ENGINE_HPP_

#include <assert.h>
#include <sys/epoll.h>
#include <unistd.h>
#ifdef EVENT_ENGINE_VERBOSE
#    include <stdio.h>
#    include <sys/syscall.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstring>
#include <deque>
#include <mutex>
#include <set>
#include <system_error>
#include <unordered_set>
#ifdef EVENT_ENGINE_VERBOSE
#    include <sstream>
#endif
#include <list>

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

    int flags() const noexcept
    {
        return flags_;
    }

    void flags(uint32_t newflag) noexcept
    {
        flags_ = newflag;
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
    uint32_t flags_ = EPOLLIN | EPOLLRDHUP | EPOLLPRI;
    bool oneshot_ = false;

    event() noexcept = default;
    explicit event(bool oneshot) noexcept
        : oneshot_(oneshot)
    {
    }
};

class engine
{
  protected:
    class timer_list
    {
        struct timer_event
        {
            void* ev;
            int64_t deadline_ms;

            bool operator<(const timer_event& rhs) const noexcept
            {
                return deadline_ms < rhs.deadline_ms;
            }
        };

      public:
        int next_expiry()
        {
            if (event_list_.empty()) {
                return -1;
            }

            int64_t remaining = std::max(event_list_.begin()->deadline_ms - now_ms(), 1L);
            assert((remaining & 0x00000000ffffffffL) == remaining);
            return (int)remaining;
        }

        void add(void* ev, int timeout_ms)
        {
            remove_(ev);

            if (timeout_ms <= 0) {
                return;
            }

            event_list_.emplace(timer_event{ev, now_ms() + timeout_ms});
            dump(__func__, ev);
        }

        void remove(void* ev)
        {
            remove_(ev);
            dump(__func__, ev);
        }

        void* pop()
        {
            assert(!event_list_.empty());
            auto it = event_list_.begin();
            auto* ev = it->ev;
            event_list_.erase(it);
            dump(__func__, ev);
            return ev;
        }

      private:
        std::set<timer_event> event_list_;

        static int64_t now_ms() noexcept
        {
            using namespace std::chrono;
            return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
        }

        void remove_(void* ev)
        {
            auto it = std::find_if(event_list_.begin(), event_list_.end(),
                                   [ev](auto& te) { return te.ev == ev; });
            if (it != event_list_.end()) {
                event_list_.erase(it);
            }
        }

        void dump(const char* func, void* ev) const noexcept
        {
            (void)func;
            (void)ev;
#if defined(EVENT_ENGINE_VERBOSE) && (EVENT_ENGINE_VERBOSE >= 2)
            bool omit = true;
            unsigned max_on_omit = 20;
            std::ostringstream ss;
            ss << " *** [" << syscall(SYS_gettid) << "] " << func << "(" << ((event*)ev)->handle()
               << "): {";
            unsigned i = 0;
            long max_deadline = 0;
            for (const auto& te : event_list_) {
                if (!omit || i < max_on_omit) {
                    ss << " {fd=" << ((event*)te.ev)->handle() << ", deadline=" << te.deadline_ms
                       << "},";
                }
                max_deadline = te.deadline_ms;
                ++i;
            }
            auto len = event_list_.size();
            ss << ((omit && len > max_on_omit) ? " ..." : "") << " } (len [" << len << "], max ["
               << max_deadline << "]) ***";
            puts(ss.str().c_str());
#endif
        }
    };  // class timer_list

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
    }

    virtual ~engine()
    {
        detail::close(epollfd_);
    }

    void register_event(event* ev, int timeout_ms = 0)
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{EV_ADD, ev, timeout_ms});
    }

    void register_timer(event* ev, int timeout_ms)
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{EV_TIM, ev, timeout_ms});
    }

    void deregister(event* ev)
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{EV_DEL, ev, 0});
    }

    void run_next()
    {
        [[maybe_unused]] bool changed = update_interest_list();

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
        [[maybe_unused]] thread_local std::string prev_log_;
        [[maybe_unused]] thread_local int ndups_ = 0;
        std::string log;
        log.reserve(256);
        for (auto i = 0; i < nfds; ++i) {
            handle_event(eev[i].data.ptr);
#ifdef EVENT_ENGINE_VERBOSE
            log += "fd=" + std::to_string(((event*)eev[i].data.ptr)->handle()) + " ";
#endif
        }
#ifdef EVENT_ENGINE_VERBOSE
        ndups_ = (changed || log != prev_log_) ? 0 : ndups_ + 1;
        if (!log.empty() && ndups_ < 3) {
            printf(" *** epoll wakeup (n=%d,c=%d): %s***\n", nfds, changed, log.c_str());
        }
        prev_log_ = log;
#endif
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
    bool update_interest_list()
    {
        bool changed = false;
        std::unique_lock<decltype(mtx_)> lk(mtx_);
        while (!requestq_.empty()) {
            changed = true;
            auto req = std::move(requestq_.front());
            requestq_.pop_front();

            if (req.op == EV_ADD) {
                add_event(req.ev, req.timeout_ms);
            } else if (req.op == EV_DEL) {
                delete_event(req.ev);
            } else if (req.op == EV_TIM) {
#ifdef EVENT_ENGINE_VERBOSE
                printf(" *** timer.add: fd=%d, ev=%p, timeout_ms=%d ***\n", req.ev->handle(),
                       req.ev, req.timeout_ms);
#endif
                timerq_.add(req.ev, req.timeout_ms);
            } else {
                // ignore
            }
        }

        return changed;
    }

    void add_event(event* ev, int timeout_ms = 0)
    {
#ifdef EVENT_ENGINE_VERBOSE
        printf(" *** add_event: fd=%d, ev=%p, timeout_ms=%d, oneshot=%d ***\n", ev->handle(), ev,
               timeout_ms, ev->oneshot());
#endif
        struct epoll_event eev;
        ::memset(&eev, 0, sizeof(eev));
        eev.events = ev->flags() | (ev->oneshot() ? EPOLLONESHOT : 0U);
        eev.data.ptr = ev;
        int op = EPOLL_CTL_ADD;
    again:
        int ret = ::epoll_ctl(epollfd_, op, ev->handle(), &eev);
        if (ret < 0) {
            if (errno == EEXIST) {
                op = EPOLL_CTL_MOD;
                goto again;
            }
            throw std::system_error(errno, std::generic_category());
        }

        timerq_.add(ev, timeout_ms);
        if (op == EPOLL_CTL_ADD) {
            ++nevents_;
        }
    }

    void delete_event(event* ev)
    {
#ifdef EVENT_ENGINE_VERBOSE
        printf(" *** delete_event: fd=%d, ev=%p ***\n", ev->handle(), ev);
#endif
        bool enoent = false;
        int ret = ::epoll_ctl(epollfd_, EPOLL_CTL_DEL, ev->handle(), nullptr);
        if (ret < 0) {
            if (!(enoent = (errno == ENOENT))) {
                throw std::system_error(errno, std::generic_category());
            }
        }

        timerq_.remove(ev);
        if (!enoent) {
            --nevents_;
        }
    }

    /**
     * event / timer callback
     */
    void handle_timeout()
    {
        auto* ev = (event*)timerq_.pop();
        if (ev->oneshot()) {
            delete_event(ev);
        }

        ev->top_half(true);
#ifdef EVENT_ENGINE_VERBOSE
        printf(" *** event timed out: fd=%d ***\n", ev->handle());
#endif
        exec_bh(ev, true);
    }

    void handle_event(void* ptr)
    {
        auto* ev = (event*)ptr;
        if (ev->oneshot()) {
            delete_event(ev);
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
