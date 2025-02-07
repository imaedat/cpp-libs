#ifndef RATE_LIMITR_HPP_
#define RATE_LIMITR_HPP_

#ifdef RATE_LIMITR_VERBOSE
#include <cstdio>
#endif
#include <chrono>
#include <cmath>

namespace tbd {

template <typename Duration>
class rate_limiter
{
  public:
    virtual ~rate_limiter() = default;
    virtual bool request(int64_t increments) = 0;

  protected:
    uint64_t limit_;
    Duration window_;

    rate_limiter(uint64_t limit, const Duration& window)
        : limit_(limit)
        , window_(window)
    {}
};

template <typename Duration>
class sliding_window_counter : public rate_limiter<Duration>
{
  public:
    sliding_window_counter(uint64_t limit, const Duration& window)
        : rate_limiter<Duration>(limit, window)
        , currwin_count_(0)
        , prevwin_count_(0)
        , next_reset_(std::chrono::steady_clock::now() + window_)
    {}

    bool request(int64_t increments) override
    {
        auto now = std::chrono::steady_clock::now();

        if (now >= next_reset_) {
            auto periods = (unsigned)std::ceil(1.0 * (now - next_reset_) / window_);
            prevwin_count_ = (periods == 1) ? currwin_count_ : 0;
            currwin_count_ = 0;
            next_reset_ += window_ * periods;
        }

        auto prevwin_weight = 1.0 * (next_reset_ - now) / window_;
        auto currwin_space = limit_ - currwin_count_ - (prevwin_count_ * prevwin_weight);
#ifdef RATE_LIMITR_VERBOSE
        printf(" *** prevwin_weight=%f, currwin_space=%f, increments=%ld ***\n", prevwin_weight,
               currwin_space, increments);
#endif
        if (increments > (int64_t)std::ceil(currwin_space)) {
            return false;
        }

        currwin_count_ += increments;
        return true;
    }

  private:
    using rate_limiter<Duration>::limit_;
    using rate_limiter<Duration>::window_;
    uint64_t currwin_count_;
    uint64_t prevwin_count_;
    std::chrono::steady_clock::time_point next_reset_;
};

}  // namespace tbd

#endif
