#ifndef EVENT_ENGINE_HPP_
#define EVENT_ENGINE_HPP_

#include <assert.h>
#include <sys/epoll.h>
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
#ifdef EVENT_ENGINE_VERBOSE
#    include <sstream>
#endif

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
    {
    }
};

class engine
{
  protected:
    struct timer_event
    {
        void* ev;
        int delta_ms;
    };

    class timer_list
    {
      public:
        int next_expiry()
        {
            return (!event_list_.empty()) ? event_list_.front().delta_ms : -1;
        }

        void add(void* ev, int timeout_ms)
        {
            update();

            if (contains(ev)) {
                remove_(ev);
            }

            if (timeout_ms <= 0) {
                return;
            }

            // assert(!contains(ev));

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

        void remove(void* ev)
        {
            update();
            remove_(ev);
            dump(__func__, ev);
        }

        void* pop()
        {
            assert(!event_list_.empty());
            update();
            auto* ev = event_list_.front().ev;
            remove_(ev);
            dump(__func__, ev);
            return ev;
        }

      private:
        std::list<timer_event> event_list_;
        std::unordered_set<void*> event_set_;
        std::chrono::steady_clock::time_point last_updated_;

        void remove_(void* ev) noexcept
        {
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
                event_list_.front().delta_ms =
                    (int)std::max(event_list_.front().delta_ms - elapsed, 0L);

                auto it = event_list_.begin();
                while (over_elapsed > 0 && ++it != event_list_.end()) {
                    auto over_elapsed_left = it->delta_ms - over_elapsed;
                    if (over_elapsed_left >= 0) {
                        it->delta_ms = (int)std::max(it->delta_ms - over_elapsed, 1L);
                        break;
                    }

                    it->delta_ms = 1;
                    over_elapsed = -over_elapsed_left;
                }
            }
        }

        bool contains(void* ev) const noexcept
        {
            return event_set_.find(ev) != event_set_.end();
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
            long total = 0;
            for (const auto& te : event_list_) {
                if (!omit || i < max_on_omit) {
                    ss << " {fd=" << ((event*)te.ev)->handle() << ", delta_ms=" << te.delta_ms
                       << "},";
                }
                total += te.delta_ms;
                ++i;
            }
            auto len = event_list_.size();
            ss << ((omit && len > max_on_omit) ? " ..." : "") << " } (len [" << len << ", total ["
               << total << "]) ***";
            puts(ss.str().c_str());
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
        std::unique_lock<decltype(mtx_)> lk(mtx_);
        bool changed = false;
        while (!requestq_.empty()) {
            changed = true;
            auto req = std::move(requestq_.front());
            requestq_.pop_front();

            if (req.op == EV_ADD) {
                add_event(req.ev->handle(), req.ev, req.timeout_ms, req.ev->oneshot());
            } else if (req.op == EV_DEL) {
                delete_event(req.ev->handle(), req.ev);
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

    void add_event(int fd, event* ev, int timeout_ms = 0, bool oneshot = false)
    {
#ifdef EVENT_ENGINE_VERBOSE
        printf(" *** add_event: fd=%d, ev=%p, timeout_ms=%d, oneshot=%d ***\n", fd, ev, timeout_ms,
               oneshot);
#endif
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

        timerq_.add(ev, timeout_ms);
        if (op == EPOLL_CTL_ADD) {
            ++nevents_;
        }
    }

    void delete_event(int fd, event* ev)
    {
#ifdef EVENT_ENGINE_VERBOSE
        printf(" *** delete_event: fd=%d, ev=%p ***\n", fd, ev);
#endif
        bool enoent = false;
        int ret = ::epoll_ctl(epollfd_, EPOLL_CTL_DEL, fd, nullptr);
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
            delete_event(ev->handle(), ev);
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
