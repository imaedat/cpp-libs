#ifndef THREAD_POOL_HPP_
#define THREAD_POOL_HPP_

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstring>
#include <deque>
#include <functional>
#include <future>
#include <list>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <variant>

#ifndef THREAD_POOL_IDLE_KEEP_ALIVE_SEC
#define THREAD_POOL_IDLE_KEEP_ALIVE_SEC 60
#endif

namespace tbd {

class thread_pool
{
    inline static constexpr size_t DEFAULT_THREADS = 8;
    inline static constexpr size_t MAX_THREADS = 16;
    inline static constexpr auto IDLE_KEEP_ALIVE =
        std::chrono::seconds(THREAD_POOL_IDLE_KEEP_ALIVE_SEC);

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

        static constexpr size_t BUFFER_SIZE = 32;
        alignas(std::max_align_t) uint8_t buffer_[BUFFER_SIZE];
        concept* fp_ = nullptr;

        bool use_sbo() const
        {
            return fp_ == reinterpret_cast<const concept*>(buffer_);
        }

      public:
        template <typename F>
        explicit task(F&& f)
        {
            using M = model<std::decay_t<F>>;
            if constexpr (sizeof(M) <= BUFFER_SIZE) {
                fp_ = new (buffer_) M(std::forward<F>(f));
            } else {
                fp_ = new M(std::forward<F>(f));
            }
        }
        task(task&& rhs) noexcept
        {
            bool use_sbo = rhs.use_sbo();
            fp_ = std::exchange(rhs.fp_, nullptr);
            if (fp_ && use_sbo) {
                ::memcpy(buffer_, rhs.buffer_, BUFFER_SIZE);
                fp_ = reinterpret_cast<concept*>(buffer_);
            }
        }
        task& operator=(task&& rhs) noexcept
        {
            if (this != &rhs) {
                this->~task();
                new (this) task(std::move(rhs));
            }
            return *this;
        }
        ~task()
        {
            if (fp_) {
                if (use_sbo()) {
                    fp_->~concept();
                } else {
                    delete fp_;
                }
                fp_ = nullptr;
            }
        }

        void operator()()
        {
            assert(fp_);
            fp_->invoke();
        }
    };
    struct shrink
    {};

    struct worker
    {
        std::atomic<bool> terminated{false};
        std::thread thr;

        template <typename F>
        worker(F&& f)
            : terminated(false)
            , thr(std::thread([this, f = std::forward<F>(f)] {
                f();
                terminated.store(true, std::memory_order_release);
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
        : max_workers_(std::max(n, (std::thread::hardware_concurrency() != 0
                                        ? std::thread::hardware_concurrency() * 2
                                        : MAX_THREADS)))
        , initial_workers_(n)
        , running_(true)
        , idle_workers_(n)
        , outstanding_tasks_(0)
        , pending_shrinks_(0)
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
        std::unique_lock lk(mtx_);

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
        std::lock_guard lk(mtx_);
        return taskq_.size();
    }

    void stop()
    {
        std::lock_guard lk(mtx_);
        running_ = false;
        cv_.notify_all();
    }

    size_t force_stop()
    {
        std::lock_guard lk(mtx_);
        auto canceled = std::count_if(taskq_.begin(), taskq_.end(), [](const auto& c) {
            return std::holds_alternative<task>(c);
        });
        assert(outstanding_tasks_ >= (size_t)canceled);
        outstanding_tasks_ -= canceled;
        taskq_.clear();
        running_ = false;
        cv_.notify_all();
        return canceled;
    }

#ifdef THREAD_POOL_ENABLE_WAIT_ALL
    void wait_all()
    {
        std::unique_lock lk(mtx_);
        cv_caller_.wait(lk, [this] { return outstanding_tasks_ == 0 && taskq_.empty(); });
    }
#endif

  private:
    const size_t max_workers_;
    const size_t initial_workers_;
    std::condition_variable cv_;
    std::mutex mtx_;
    bool running_;
    std::list<worker> workers_;
    std::deque<std::variant<task, shrink>> taskq_;
    size_t idle_workers_;
    size_t outstanding_tasks_;
    size_t pending_shrinks_;
#ifdef THREAD_POOL_ENABLE_WAIT_ALL
    std::condition_variable cv_caller_;
#endif

    void executor() noexcept
    {
        std::unique_lock lk(mtx_);

        while (true) {
            auto wr = wait_task(lk);
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
                lk.unlock();

                auto& task = std::get<thread_pool::task>(cmd);
                task();

                lk.lock();
                assert(outstanding_tasks_ > 0);
                --outstanding_tasks_;

            } else {
                assert(std::holds_alternative<shrink>(cmd));
                shrink_worker();
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
        if (idle_workers_ == 0 && taskq_.size() > workers_.size() &&
            workers_.size() < max_workers_) {
            workers_.emplace_back([this] { executor(); });
            ++idle_workers_;
            // puts("glow");
        }
#endif
    }

    void shrink_worker()
    {
        if (pending_shrinks_ > 0) {
            auto befores = workers_.size();
            workers_.remove_if([&](const auto& w) -> bool {
                return w.terminated.load(std::memory_order_acquire);
            });
            assert(pending_shrinks_ >= befores - workers_.size());
            pending_shrinks_ -= (befores - workers_.size());
        }
    }

    enum class wait_result
    {
        wr_break,
        wr_continue,
        wr_return,
    };
    template <typename L>
    wait_result wait_task(L& lk)
    {
#ifdef THREAD_POOL_ENABLE_DYNAMIC_RESIZE
        auto notified =
            cv_.wait_for(lk, IDLE_KEEP_ALIVE, [this] { return !running_ || !taskq_.empty(); });
        if (notified) {
            return wait_result::wr_break;
        }

        assert(workers_.size() > pending_shrinks_);
        if (workers_.size() - pending_shrinks_ <= initial_workers_) {
            return wait_result::wr_continue;
        }

        assert(idle_workers_ > 0);
        --idle_workers_;
        taskq_.emplace_back(shrink{});
        ++pending_shrinks_;
        lk.unlock();
        cv_.notify_all();
        // puts("shrink");
        return wait_result::wr_return;

#else
        cv_.wait(lk, [this] { return !running_ || !taskq_.empty(); });
        return wait_result::wr_break;
#endif
    }
};

}  // namespace tbd

#endif
