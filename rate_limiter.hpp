#ifndef RATE_LIMITR_HPP_
#define RATE_LIMITR_HPP_

#ifdef RATE_LIMITR_VERBOSE
#include <cstdio>
#endif
#include <chrono>
#include <cmath>
#include <deque>

namespace tbd {

/****************************************************************************
 * Base Class
 */
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

/****************************************************************************
 * Token Bucket
 */
template <typename Duration>
class token_bucket : public rate_limiter<Duration>
{
  public:
    token_bucket(uint64_t limit, const Duration& window)
        : rate_limiter<Duration>(limit, window)
        , tokens_left_(limit_)
    {}

    bool request(int64_t increments) override
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = now - prev_requested_;

        if (elapsed >= window_) {
            tokens_left_ = limit_;
        } else {
            auto acquires = (unsigned)std::round(1.0 * limit_ * elapsed / window_);
            tokens_left_ = std::min(tokens_left_ + acquires, limit_);
        }
        prev_requested_ = now;
#ifdef RATE_LIMITR_VERBOSE
        printf(" *** elapsed=%lu ms, tokens_left_=%lu, increments=%ld ***\n",
               std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), tokens_left_,
               increments);
#endif

        if (increments > (int64_t)tokens_left_) {
            return false;
        }

        tokens_left_ -= increments;
        return true;
    }

  private:
    using rate_limiter<Duration>::limit_;
    using rate_limiter<Duration>::window_;
    uint64_t tokens_left_;
    std::chrono::steady_clock::time_point prev_requested_;
};

/****************************************************************************
 * Sliding Window Log
 */
template <typename Duration>
class sliding_window_log : public rate_limiter<Duration>
{
  public:
    sliding_window_log(uint64_t limit, const Duration& window)
        : rate_limiter<Duration>(limit, window)
    {}

    bool request(int64_t increments) override
    {
        auto now = std::chrono::steady_clock::now();

        uint64_t amount_in_window = 0;
        auto begging_of_window = now - window_;
        auto begin = log_.cbegin();
        bool contains_expired = false;
        for (auto it = log_.cbegin(); it != log_.cend(); ++it) {
            if (it->arrived_at >= begging_of_window) {
                amount_in_window += it->quantity;
            } else {
                begin = it;
                contains_expired = true;
                break;
            }
        }

#ifdef RATE_LIMITR_VERBOSE
        auto before = log_.size();
#endif
        if (contains_expired) {
            log_.erase(begin, log_.cend());
        }
#ifdef RATE_LIMITR_VERBOSE
        auto after = log_.size();
        auto nerase = before - after;
        if (amount_in_window + increments <= limit_) {
            ++after;
        }
        printf(" *** nerase=%lu, qsize=%lu, amount_in_window=%lu, increments=%ld ***\n", nerase,
               after, amount_in_window, increments);
#endif

        if (amount_in_window + increments > limit_) {
            return false;
        }

        log_.emplace_front(log_entry{now, (uint64_t)increments});
        return true;
    }

  private:
    struct log_entry
    {
        std::chrono::steady_clock::time_point arrived_at;
        uint64_t quantity;
    };

    using rate_limiter<Duration>::limit_;
    using rate_limiter<Duration>::window_;
    std::deque<log_entry> log_;  // (head) new <-> old (tail)
};

/****************************************************************************
 * Sliding Window Counter
 */
template <typename Duration>
class sliding_window_counter : public rate_limiter<Duration>
{
  public:
    sliding_window_counter(uint64_t limit, const Duration& window)
        : rate_limiter<Duration>(limit, window)
        , currwin_amount_(0)
        , prevwin_amount_(0)
        , next_reset_(std::chrono::steady_clock::now() + window_)
    {}

    bool request(int64_t increments) override
    {
        auto now = std::chrono::steady_clock::now();

        if (now >= next_reset_) {
            auto periods = (unsigned)std::ceil(1.0 * (now - next_reset_) / window_);
            prevwin_amount_ = (periods == 1) ? currwin_amount_ : 0;
            currwin_amount_ = 0;
            next_reset_ += window_ * periods;
        }

        auto prevwin_weight = 1.0 * (next_reset_ - now) / window_;
        auto currwin_space = limit_ - currwin_amount_ - (prevwin_amount_ * prevwin_weight);
#ifdef RATE_LIMITR_VERBOSE
        printf(" *** prevwin_weight=%f, currwin_space=%f, increments=%ld ***\n", prevwin_weight,
               currwin_space, increments);
#endif
        if (increments > (int64_t)std::ceil(currwin_space)) {
            return false;
        }

        currwin_amount_ += increments;
        return true;
    }

  private:
    using rate_limiter<Duration>::limit_;
    using rate_limiter<Duration>::window_;
    uint64_t currwin_amount_;
    uint64_t prevwin_amount_;
    std::chrono::steady_clock::time_point next_reset_;
};

}  // namespace tbd

#endif
