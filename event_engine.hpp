#ifndef EVENT_ENGINE_HPP_
#define EVENT_ENGINE_HPP_

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstring>
#include <deque>
#include <list>
#include <memory>
#include <mutex>
#include <set>
#include <system_error>
#include <unordered_set>

#ifdef EVENT_ENGINE_VERBOSE  // {{{
#include <sstream>
#include <stdio.h>
#include <sys/syscall.h>
#endif  // }}}

namespace tbd {

namespace detail {
inline void close(int& fd) noexcept
{
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}
}  // namespace detail

class event;
class engine;

class task
{
  public:
    task(const task&) = delete;
    task& operator=(const task&) = delete;
    task(task&&) noexcept = default;
    task& operator=(task&&) noexcept = default;
    virtual ~task() noexcept = default;

  protected:
    tbd::engine* engine_ = nullptr;
    std::unique_ptr<std::atomic<bool>> running_;  // make movable
    std::unique_ptr<std::atomic<bool>> pending_;

    task(tbd::engine* eng)
        : engine_(eng)
        , running_(std::make_unique<std::atomic<bool>>(false))
        , pending_(std::make_unique<std::atomic<bool>>(false))
    {
    }

    virtual void top_half(event*)
    {
        // urgent work
    }

    virtual void bottom_half(event*)
    {
        // non-urgent, follow-up work
    }

    bool enter() noexcept
    {
        bool expected = false;
        bool ok = running_->compare_exchange_strong(expected, true);
        *pending_ = !ok;
        return ok;
    }

    void exit() noexcept;

    tbd::engine* engine() const noexcept
    {
        return engine_;
    }

    friend class event;
    friend class engine;
};

class event
{
  public:
    event(const event&) = delete;
    event& operator=(const event&) = delete;
    event(event&& rhs) noexcept
        : fd_(rhs.fd_)
        , task_(rhs.task_)
        , flags_(rhs.flags_)
        , ready_(std::move(rhs.ready_))
    {
        rhs.fd_ = -1;
        rhs.task_ = nullptr;
        rhs.flags_ = DEFAULT_FLAGS;
    }
    event& operator=(event&& rhs) noexcept
    {
        using std::swap;
        if (this != &rhs) {
            swap(fd_, rhs.fd_);
            swap(task_, rhs.task_);
            swap(flags_, rhs.flags_);
            swap(ready_, rhs.ready_);
        }
        return *this;
    }

    virtual ~event() noexcept
    {
        detail::close(fd_);
    }

    int handle() const noexcept
    {
        return fd_;
    }

    int flags() const noexcept
    {
        return flags_;
    }

    void flags(uint32_t newflag) noexcept
    {
        flags_ = newflag;
    }

    bool ready() const noexcept
    {
        return *ready_;
    }

    void async_wait(int timeout_ms = 0);
    void async_timer(int timeout_ms);
    void stop();

  protected:
    inline static constexpr uint32_t DEFAULT_FLAGS = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLONESHOT;

    int fd_ = -1;
    tbd::task* task_ = nullptr;
    uint32_t flags_ = DEFAULT_FLAGS;
    std::unique_ptr<std::atomic<bool>> ready_;

    explicit event(tbd::task* task) noexcept
        : task_(task)
        , ready_(std::make_unique<std::atomic<bool>>(false))
    {
    }

    tbd::task* task() const noexcept
    {
        return task_;
    }

    void set_ready(bool set = true) noexcept
    {
        *ready_ = set;
    }

    friend class engine;
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
                return (deadline_ms != rhs.deadline_ms) ? (deadline_ms < rhs.deadline_ms)
                                                        : (ev < rhs.ev);
            }
        };

      public:
        // returns -1 if empty; wait indefinitely
        int next_expiry()
        {
            if (event_list_.empty()) {
                return -1;
            }

            int64_t remaining = std::max(event_list_.begin()->deadline_ms - now_ms(), 0L);
            assert((remaining & 0x00000000ffffffffL) == remaining);
            return (int)remaining;
        }

        void add(void* ev, int timeout_ms)
        {
            remove_(ev);

            if (timeout_ms <= 0) {
                return;
            }

            [[maybe_unused]] auto it = event_list_.emplace(timer_event{ev, now_ms() + timeout_ms});
#ifdef EVENT_ENGINE_USE_TIMER_MAP
            event_pos_.emplace(ev, it);
#endif
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
#ifdef EVENT_ENGINE_USE_TIMER_MAP
            event_pos_.erase(ev);
#endif
            dump(__func__, ev);
            return ev;
        }

        const timer_event* peek() const
        {
            return &(*event_list_.cbegin());
        }

      private:
        std::multiset<timer_event> event_list_;
#ifdef EVENT_ENGINE_USE_TIMER_MAP
        std::unordered_map<void*, decltype(event_list_.begin())> event_pos_;
#endif

        static int64_t now_ms() noexcept
        {
            using namespace std::chrono;
            return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
        }

        void remove_(void* ev)
        {
#ifdef EVENT_ENGINE_USE_TIMER_MAP
            {
                auto it = event_pos_.find(ev);
                if (it != event_pos_.end()) {
                    event_list_.erase(it->second);
                    event_pos_.erase(it);
                }
                return;
            }
#endif
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
#if defined(EVENT_ENGINE_VERBOSE) && (EVENT_ENGINE_VERBOSE >= 2)  // {{{
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
#endif  // }}}
        }
    };  // class timer_list

    enum op
    {
        EV_ADD = 1,
        EV_DEL = 2,
        EV_TIM = 3,
        EV_TERM,
    };

    struct terminate
    {};

    struct event_request
    {
        enum op op;
        event* ev;
        int timeout_ms;
    };

    int epollfd_ = -1;
    int eventfd_ = -1;
    int nevents_ = 0;
    std::mutex mtx_;
    std::deque<event_request> requestq_;
    timer_list timerq_;
    std::deque<event*> pendingq_;

  public:
    engine()
    {
        epollfd_ = ::epoll_create1(0);
        if (epollfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }
        eventfd_ = ::eventfd(0, EFD_NONBLOCK);
        if (eventfd_ < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        struct epoll_event eev = {};
        eev.events = EPOLLIN;
        eev.data.ptr = this;
        if (::epoll_ctl(epollfd_, EPOLL_CTL_ADD, eventfd_, &eev) < 0) {
            throw std::system_error(errno, std::generic_category());
        }
        ++nevents_;
    }

    virtual ~engine() noexcept
    {
        detail::close(epollfd_);
        detail::close(eventfd_);
    }

    void stop()
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{EV_TERM, nullptr, 0});
        notify();
    }

    void run_next()
    {
        [[maybe_unused]] thread_local bool changed_ = true;

    again:
        struct epoll_event eev[nevents_] = {};
        int nfds = ::epoll_wait(epollfd_, eev, nevents_, timerq_.next_expiry());
        if (nfds < 0) {
            if (errno == EINTR) {
                goto again;
            }
            throw std::system_error(errno, std::generic_category());
        }

        if (nfds == 0) {
            handle_timeout();

        } else {
            assert(nfds >= 1);
            [[maybe_unused]] thread_local int ndups_ = 0;
            [[maybe_unused]] thread_local std::string prev_log_;
            std::string log;
            log.reserve(256);
            for (auto i = 0; i < nfds; ++i) {
                if (eev[i].data.ptr == this) {
                    continue;  // skip
                }

                handle_event((event*)eev[i].data.ptr);
#ifdef EVENT_ENGINE_VERBOSE  // {{{
                log += "fd=" + std::to_string(((event*)eev[i].data.ptr)->handle()) + " ";
#endif  // }}}
            }
#ifdef EVENT_ENGINE_VERBOSE  // {{{
            ndups_ = (changed_ || log != prev_log_) ? 0 : ndups_ + 1;
            if (!log.empty() && ndups_ < 3) {
                printf(" *** epoll wakeup (n=%d,c=%d): %s***\n", nfds, changed_, log.c_str());
            }
            prev_log_ = log;
#endif  // }}}
        }

        changed_ = handle_request();
        flush_pendings();
    }

    void run_loop()
    {
        try {
            while (true) {
                run_next();
            }
        } catch (const terminate&) {
            // nop
        }
    }

  protected:
    void register_event(event* ev, int timeout_ms = 0)
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{EV_ADD, ev, timeout_ms});
        notify();
    }

    void register_timer(event* ev, int timeout_ms)
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{EV_TIM, ev, timeout_ms});
        notify();
    }

    void deregister(event* ev)
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        requestq_.emplace_back(event_request{EV_DEL, ev, 0});
        notify();
    }

    void notify()
    {
        ::eventfd_write(eventfd_, 1);
    }

    /**
     * add new / delete existing event
     */
    bool handle_request()
    {
        bool changed = false;
        std::unique_lock<decltype(mtx_)> lk(mtx_);
        while (!requestq_.empty()) {
            changed = true;
            auto req = std::move(requestq_.front());
            requestq_.pop_front();

            switch (req.op) {
            case EV_ADD:
                add_event(req.ev, req.timeout_ms);
                req.ev->set_ready(false);
                break;

            case EV_DEL:
                delete_event(req.ev);
                req.ev->set_ready(false);
                break;

            case EV_TIM:
#ifdef EVENT_ENGINE_VERBOSE  // {{{
                printf(" *** timer.add: fd=%d, ev=%p, timeout_ms=%d ***\n", req.ev->handle(),
                       req.ev, req.timeout_ms);
#endif  // }}}
                timerq_.add(req.ev, req.timeout_ms);
                req.ev->set_ready(false);
                break;

            case EV_TERM:
                throw terminate{};

            default:
                break;  // ignore
            }
        }

        eventfd_t value;
        ::eventfd_read(eventfd_, &value);
        return changed;
    }

    void add_event(event* ev, int timeout_ms = 0)
    {
#ifdef EVENT_ENGINE_VERBOSE  // {{{
        printf(" *** add_event: fd=%d, ev=%p, timeout_ms=%d ***\n", ev->handle(), ev, timeout_ms);
#endif  // }}}
        struct epoll_event eev = {};
        eev.events = ev->flags();
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
#ifdef EVENT_ENGINE_VERBOSE  // {{{
        printf(" *** delete_event: fd=%d, ev=%p ***\n", ev->handle(), ev);
#endif  // }}}
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

    void flush_pendings()
    {
        std::string log;
        log.reserve(256);
        [[maybe_unused]] auto before = pendingq_.size();
        for (auto it = pendingq_.begin(); it != pendingq_.end();) {
#ifdef EVENT_ENGINE_VERBOSE  // {{{
            log += "fd=" + std::to_string((*it)->handle());
#endif  // }}}
            if (exec_bh(*it)) {
                it = pendingq_.erase(it);
#ifdef EVENT_ENGINE_VERBOSE  // {{{
                log += "(o) ";
#endif  // }}}
            } else {
                ++it;
#ifdef EVENT_ENGINE_VERBOSE  // {{{
                log += "(x) ";
#endif  // }}}
            }
        }
#ifdef EVENT_ENGINE_VERBOSE  // {{{
        auto after = pendingq_.size();
        if (before > 0 || before != after) {
            printf(" *** flush_pendings: #pend %lu -> %lu, %s***\n", before, after, log.c_str());
        }
#endif  // }}}
    }

    /**
     * timer callback
     */
    void handle_timeout()
    {
        int n = 0;
        std::string log;
        log.reserve(256);
        auto first_deadline = timerq_.peek()->deadline_ms;
        while (timerq_.peek()->deadline_ms == first_deadline) {
            auto* ev = (event*)timerq_.pop();
            delete_event(ev);
            ev->task()->top_half(ev);
#ifdef EVENT_ENGINE_VERBOSE  // {{{
            ++n;
            log += "fd=" + std::to_string(ev->handle()) + " ";
#endif  // }}}
            if (!exec_bh(ev)) {
#ifdef EVENT_ENGINE_VERBOSE  // {{{
                printf(" *** handle_timeout: exec_bh failed, fd=%d, ev=%p ***\n", ev->handle(), ev);
#endif  // }}}
                pendingq_.emplace_back(ev);
            }
        }
#ifdef EVENT_ENGINE_VERBOSE  // {{{
        printf(" *** event timed out (n=%d): %s***\n", n, log.c_str());
#endif  // }}}
    }

    /**
     * event callback
     */
    void handle_event(event* ev)
    {
        if (ev->flags() & EPOLLONESHOT) {
            timerq_.remove(ev);
        } else {
            delete_event(ev);
        }
        ev->set_ready();
        ev->task()->top_half(ev);
        if (!exec_bh(ev)) {
#ifdef EVENT_ENGINE_VERBOSE  // {{{
            printf(" *** handle_event: exec_bh failed, fd=%d, ev=%p ***\n", ev->handle(), ev);
#endif  // }}}
        }
    }

    virtual bool exec_bh(event* ev)
    {
        ev->task()->bottom_half(ev);
        return true;
    }

    // helpers
    static bool task_enter(event* ev) noexcept
    {
        return ev->task()->enter();
    }

    static void task_exit(event* ev) noexcept
    {
        ev->task()->exit();
    }

    static void task_execute(event* ev)
    {
        ev->task()->bottom_half(ev);
        ev->task()->exit();
    }

    friend class task;
    friend class event;
};

void task::exit() noexcept
{
    *running_ = false;
    bool expected = false;
    if (!pending_->compare_exchange_strong(expected, false)) {
#ifdef EVENT_ENGINE_VERBOSE  // {{{
        printf(" *** task::exit: notify to engine ***\n");
#endif  // }}}
        engine_->notify();
    }
}

void event::async_wait(int timeout_ms)
{
    task_->engine()->register_event(this, timeout_ms);
}

void event::async_timer(int timeout_ms)
{
    task_->engine()->register_timer(this, timeout_ms);
}

void event::stop()
{
    task_->engine()->deregister(this);
}

/**********************************************************************
// multithread example
#include "thread_pool.hpp"
struct multithreaded_engine : public engine
{
    thread_pool pool_;

    bool exec_bh(event* ev) override
    {
        if (!task_enter(ev)) {
            return false;
        }

        pool_.submit([ev] { task_execute(ev); });
        return true;
    }
};
***********************************************************************/

}  // namespace tbd

#endif

/* vi: set foldmethod=marker: */
