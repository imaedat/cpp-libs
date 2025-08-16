#ifndef THREAD_POOL_HPP_
#define THREAD_POOL_HPP_

#include <cassert>
#include <condition_variable>
#include <deque>
#include <functional>
#include <stdexcept>
#include <thread>
#include <type_traits>
#include <vector>

namespace tbd {

class thread_pool
{
  public:
    explicit thread_pool(size_t n = (std::thread::hardware_concurrency() != 0
                                         ? std::thread::hardware_concurrency()
                                         : 8))
        : running_(true)
#ifdef THREAD_POOL_ENABLE_WAIT_ALL
        , noutstandings_(0)
#endif
    {
        for (size_t i = 0; i < n; ++i) {
            workers_.emplace_back([this] { executor(); });
        }
    }

    ~thread_pool(void)
    {
        stop();
        for (auto&& w : workers_) {
            if (w.joinable()) {
                w.join();
            }
        }
    }

    template <typename F, typename = std::enable_if_t<std::is_invocable_v<F>>>
    void submit(F&& fn)
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);

        if (!running_) {
            throw std::runtime_error("thread_pool not running");
        }

        taskq_.emplace_back(std::forward<F>(fn));
#ifdef THREAD_POOL_ENABLE_WAIT_ALL
        ++noutstandings_;
#endif
        cv_.notify_one();
    }

    void stop(void)
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        running_ = false;
        cv_.notify_all();
    }

    size_t force_stop(void)
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        auto canceled = taskq_.size();
#ifdef THREAD_POOL_ENABLE_WAIT_ALL
        noutstandings_ -= canceled;
#endif
        taskq_.clear();
        running_ = false;
        cv_.notify_all();
        return canceled;
    }

#ifdef THREAD_POOL_ENABLE_WAIT_ALL
    void wait_all(void)
    {
        std::unique_lock<decltype(mtx_)> lk(mtx_);
        cv_caller_.wait(lk, [this] { return noutstandings_ == 0 && taskq_.empty(); });
    }
#endif

  private:
    bool running_;
    std::vector<std::thread> workers_;
    std::deque<std::function<void(void)>> taskq_;
    std::mutex mtx_;
    std::condition_variable cv_;
#ifdef THREAD_POOL_ENABLE_WAIT_ALL
    size_t noutstandings_;
    std::condition_variable cv_caller_;
#endif

    void executor(void)
    {
        std::unique_lock<decltype(mtx_)> ul(mtx_);

        while (true) {
            cv_.wait(ul, [this] { return !running_ || !taskq_.empty(); });
            if (!running_ && taskq_.empty()) {
                return;
            }

            assert(!taskq_.empty());
            auto task = std::move(taskq_.front());
            taskq_.pop_front();
            ul.unlock();

            task();

            ul.lock();
#ifdef THREAD_POOL_ENABLE_WAIT_ALL
            if (--noutstandings_ == 0 && taskq_.empty()) {
                cv_caller_.notify_all();
            }
#endif
        }
    }
};

}  // namespace tbd

#endif
