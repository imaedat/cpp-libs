#ifndef WAIT_GROUP_HPP_
#define WAIT_GROUP_HPP_

#include <chrono>
#include <condition_variable>
#include <mutex>

namespace tbd {

class wait_group
{
  public:
    explicit wait_group(int initial = 0) noexcept
        : counter_(initial)
    {
    }

    ~wait_group() noexcept = default;

    void add(int delta = 1)
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        if (counter_ + delta < 0) {
            throw std::invalid_argument("wait_group::add: invalid delta");
        }

        counter_ += delta;
        if (counter_ == 0) {
            cv_.notify_all();
        }
    }

    void done()
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        if (--counter_ == 0) {
            cv_.notify_all();
        }
    }

    bool wait(int wait_ms = -1)
    {
        std::unique_lock<decltype(mtx_)> lk(mtx_);
        if (wait_ms >= 0) {
            return cv_.wait_for(lk, std::chrono::milliseconds(wait_ms),
                                [this] { return counter_ == 0; });
        }

        cv_.wait(lk, [this] { return counter_ == 0; });
        return true;
    }

  private:
    int counter_ = 0;
    std::mutex mtx_;
    std::condition_variable cv_;
};

}  // namespace tbd

#endif
