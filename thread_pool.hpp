#ifndef THREAD_POOL_HPP_
#define THREAD_POOL_HPP_

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <list>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <variant>

namespace tbd {

class thread_pool
{
    inline static constexpr size_t DEFAULT_THREADS = 8;
    inline static constexpr size_t MAX_THREADS = 64;
    inline static constexpr auto IDLE_KEEP_ALIVE = std::chrono::seconds(60);

    class task
    {
        struct concept
        {
            virtual void invoke() = 0;
            virtual ~concept() = default;
        };
        template <typename F>
        struct model : concept
        {
            F f;
            explicit model(F&& f)
                : f(std::move(f))
            {
            }
            void invoke() override
            {
                f();
            }
        };

        std::unique_ptr<concept> fp_;

      public:
        template <typename F>
        explicit task(F&& f)
            : fp_(std::make_unique<model<F>>(std::move(f)))
        {
        }
        task(task&&) noexcept = default;
        task& operator=(task&&) noexcept = default;
        void operator()()
        {
            fp_->invoke();
        }
    };
    struct shrink
    {};

    struct worker
    {
        std::atomic<bool> terminated;
        std::thread thr;

        template <typename F>
        worker(F&& f)
            : terminated(false)
            , thr(std::thread([this, f = std::forward<F>(f)] {
                f();
                terminated = true;
            }))
        {
        }
        ~worker()
        {
            if (thr.joinable()) {
                thr.join();
            }
        }
    };

  public:
    explicit thread_pool(size_t n = (std::thread::hardware_concurrency() != 0
                                         ? std::thread::hardware_concurrency()
                                         : DEFAULT_THREADS))
        : max_workers_(std::thread::hardware_concurrency() != 0
                           ? std::thread::hardware_concurrency() * 2
                           : MAX_THREADS)
        , running_(true)
        , idle_workers_(n)
        , outstanding_tasks_(0)
    {
        assert(n > 0);
        for (size_t i = 0; i < n; ++i) {
            workers_.emplace_back([this] { executor(); });
        }
    }

    ~thread_pool()
    {
        stop();
        workers_.clear();
    }

    template <typename F, typename... Args,
              typename R = std::invoke_result_t<std::decay_t<F>, std::decay_t<Args>...>>
    std::future<R> submit(F&& fn, Args&&... args)
    {
        std::unique_lock<decltype(mtx_)> lk(mtx_);

        if (!running_) {
            throw std::runtime_error("thread_pool not running");
        }

        std::packaged_task<R()> pkgt(
            [fn = std::forward<F>(fn),
             args = std::make_tuple(std::forward<Args>(args)...)]() mutable {
                return std::apply(fn, std::move(args));
            });
        auto fut = pkgt.get_future();
        taskq_.emplace_back(task([pkgt = std::move(pkgt)]() mutable { pkgt(); }));
        ++outstanding_tasks_;
        grow_worker();
        lk.unlock();
        cv_.notify_one();
        return fut;
    }

    size_t queue_size()
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        return taskq_.size();
    }

    void stop()
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        running_ = false;
        cv_.notify_all();
    }

    size_t force_stop()
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        auto canceled = taskq_.size();
        outstanding_tasks_ -= canceled;
        taskq_.clear();
        running_ = false;
        cv_.notify_all();
        return canceled;
    }

#ifdef THREAD_POOL_ENABLE_WAIT_ALL
    void wait_all()
    {
        std::unique_lock<decltype(mtx_)> lk(mtx_);
        cv_caller_.wait(lk, [this] { return outstanding_tasks_ == 0 && taskq_.empty(); });
    }
#endif

  private:
    const size_t max_workers_;
    std::condition_variable cv_;
    std::mutex mtx_;
    bool running_;
    std::list<worker> workers_;
    std::deque<std::variant<task, shrink>> taskq_;
    size_t idle_workers_;
    size_t outstanding_tasks_;
#ifdef THREAD_POOL_ENABLE_WAIT_ALL
    std::condition_variable cv_caller_;
#endif

    void executor() noexcept
    {
        std::unique_lock<decltype(mtx_)> ul(mtx_);

        while (true) {
            auto wr = wait_task(ul);
            if (wr == wait_result::wr_continue) {
                continue;
            }
            if (wr == wait_result::wr_return || (!running_ && taskq_.empty())) {
                return;
            }

            assert(wr == wait_result::wr_break);
            assert(!taskq_.empty());
            auto cmd = std::move(taskq_.front());
            taskq_.pop_front();
            assert(idle_workers_ > 0);
            --idle_workers_;

            if (std::holds_alternative<task>(cmd)) {
                ul.unlock();

                auto& task = std::get<thread_pool::task>(cmd);
                task();

                ul.lock();
                --outstanding_tasks_;

            } else {
                assert(std::holds_alternative<shrink>(cmd));
                workers_.remove_if([](const auto& w) -> bool { return w.terminated; });
            }

            ++idle_workers_;
#ifdef THREAD_POOL_ENABLE_WAIT_ALL
            if (outstanding_tasks_ == 0 && taskq_.empty()) {
                cv_caller_.notify_all();
            }
#endif
        }
    }

    void grow_worker()
    {
#ifdef THREAD_POOL_ENABLE_DYNAMIC_RESIZE
        if (idle_workers_ == 0 && taskq_.size() > DEFAULT_THREADS &&
            workers_.size() < max_workers_) {
            workers_.emplace_back([this] { executor(); });
            ++idle_workers_;
        }
#endif
    }

    enum class wait_result
    {
        wr_break,
        wr_continue,
        wr_return,
    };
    template <typename L>
    wait_result wait_task(L& ul)
    {
#ifdef THREAD_POOL_ENABLE_DYNAMIC_RESIZE
        auto notified =
            cv_.wait_for(ul, IDLE_KEEP_ALIVE, [this] { return !running_ || !taskq_.empty(); });
        if (notified) {
            return wait_result::wr_break;
        }

        if (workers_.size() == DEFAULT_THREADS) {
            return wait_result::wr_continue;
        }

        assert(idle_workers_ > 0);
        --idle_workers_;
        taskq_.emplace_back(shrink{});
        return wait_result::wr_return;

#else
        cv_.wait(ul, [this] { return !running_ || !taskq_.empty(); });
        return wait_result::wr_break;
#endif
    }
};

}  // namespace tbd

#endif
