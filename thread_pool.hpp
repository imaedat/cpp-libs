#ifndef THREAD_POOL_HPP_
#define THREAD_POOL_HPP_

#include <cassert>
#include <condition_variable>
#include <deque>
#include <functional>
#include <stdexcept>
#include <thread>
#include <vector>

namespace tbd {

class thread_pool
{
  public:
    thread_pool(size_t n = (std::thread::hardware_concurrency() != 0
                                ? std::thread::hardware_concurrency()
                                : 8))
        : running_(true)
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

    void submit(std::function<void(void)>&& fn)
    {
        if (!running_) {
            throw std::runtime_error("thread_pool not running");
        }

        std::lock_guard<std::mutex> lk(mtx_);
        taskq_.emplace_back(std::forward<std::function<void(void)>>(fn));
        cv_.notify_one();
    }

    void stop(void)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        running_ = false;
        cv_.notify_all();
    }

    void force_stop(void)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        taskq_.clear();
        running_ = false;
        cv_.notify_all();
    }

#ifdef THREAD_POOL_ENABLE_WAIT_ALL
    void wait_all(void)
    {
        std::unique_lock<std::mutex> lk(mtx_);
        cv_caller_.wait(lk, [this] { return taskq_.empty(); });
    }
#endif

  private:
    bool running_;
    std::vector<std::thread> workers_;
    std::deque<std::function<void(void)>> taskq_;
    std::mutex mtx_;
    std::condition_variable cv_;
#ifdef THREAD_POOL_ENABLE_WAIT_ALL
    std::condition_variable cv_caller_;
#endif

    void executor(void)
    {
        while (true) {
            std::unique_lock<std::mutex> lk(mtx_);
#ifdef THREAD_POOL_ENABLE_WAIT_ALL
            if (taskq_.empty()) {
                cv_caller_.notify_one();
            }
#endif
            cv_.wait(lk, [this] { return !running_ || !taskq_.empty(); });
            if (!running_ && taskq_.empty()) {
                break;
            }

            assert(!taskq_.empty());
            auto task = std::move(taskq_.front());
            taskq_.pop_front();
            lk.unlock();

            task();
        }
    }
};

}  // namespace tdb

#endif
