#ifndef RATE_LIMITR_HPP_
#define RATE_LIMITR_HPP_

#include <chrono>
#include <cmath>
#ifdef RATE_LIMITR_VERBOSE
#    include <cstdio>
#endif
#include <deque>

namespace tbd {

/****************************************************************************
 * Base Class
 */
class rate_limiter
{
  public:
    virtual ~rate_limiter() noexcept = default;
    virtual bool try_request(int64_t quantity) = 0;

  protected:
    uint64_t limit_;
    std::chrono::nanoseconds window_;

    template <typename Duration>
    rate_limiter(uint64_t limit, Duration window)
        : limit_(limit)
        , window_(window)
    {
    }
};

/****************************************************************************
 * Token Bucket
 */
class token_bucket : public rate_limiter
{
  public:
    template <typename Duration>
    token_bucket(uint64_t limit, Duration window)
        : rate_limiter(limit, window)
        , tokens_left_(limit_)
    {
    }

    bool try_request(int64_t quantity) override
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = now - last_requested_;

        [[maybe_unused]] unsigned refills = 0;
        if (elapsed >= window_) {
            tokens_left_ = limit_;
        } else {
            refills = (unsigned)std::round(1.0 * limit_ * elapsed / window_);
            tokens_left_ = std::min(tokens_left_ + refills, limit_);
        }
        last_requested_ = now;
#ifdef RATE_LIMITR_VERBOSE
        printf(
            " *** [token_bucket] elapsed=%lu ms, refills=%u, tokens_left_=%lu, quantity=%ld ***\n",
            std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), refills,
            tokens_left_, quantity);
#endif

        if (quantity > (int64_t)tokens_left_) {
            return false;
        }

        tokens_left_ -= quantity;
        return true;
    }

  private:
    uint64_t tokens_left_;
    std::chrono::steady_clock::time_point last_requested_;
};

/****************************************************************************
 * Sliding Window Log
 */
class sliding_window_log : public rate_limiter
{
  public:
    template <typename Duration>
    sliding_window_log(uint64_t limit, Duration window)
        : rate_limiter(limit, window)
        , amount_in_window_(0)
    {
    }

    bool try_request(int64_t quantity) override
    {
        auto now = std::chrono::steady_clock::now();
        auto beginning_of_window = now - window_;
#ifdef RATE_LIMITR_VERBOSE
        auto before = log_.size();
#endif
        while (!log_.empty() && log_.front().arrived_at < beginning_of_window) {
            amount_in_window_ -= log_.front().quantity;
            log_.pop_front();
        }

#ifdef RATE_LIMITR_VERBOSE
        auto qsize = log_.size();
        auto nerased = before - qsize;
        bool ok = (amount_in_window_ + quantity <= (int64_t)limit_);
        printf(
            " *** [sliding_window_log] nerased=%lu, qsize=%lu, amount_in_window_=%lu, quantity=%ld, result=%s ***\n",
            nerased, qsize, amount_in_window_, quantity, (ok ? "ok" : "ng"));
#endif

        if (amount_in_window_ + quantity > (int64_t)limit_) {
            return false;
        }

        log_.emplace_back(log_entry{now, (uint64_t)quantity});
        amount_in_window_ += quantity;
        return true;
    }

  private:
    struct log_entry
    {
        std::chrono::steady_clock::time_point arrived_at;
        uint64_t quantity;
    };

    int64_t amount_in_window_;
    std::deque<log_entry> log_;  // (head) old <-> new (tail)
};

/****************************************************************************
 * Sliding Window Counter
 */
class sliding_window_counter : public rate_limiter
{
  public:
    template <typename Duration>
    sliding_window_counter(uint64_t limit, Duration window)
        : rate_limiter(limit, window)
        , currwin_amount_(0)
        , prevwin_amount_(0)
        , end_of_window_(std::chrono::steady_clock::now() + window_)
    {
    }

    bool try_request(int64_t quantity) override
    {
        auto now = std::chrono::steady_clock::now();

        if (now >= end_of_window_) {
            auto periods = (unsigned)std::ceil(1.0 * (now - end_of_window_) / window_);
            prevwin_amount_ = (periods == 1) ? currwin_amount_ : 0;
            currwin_amount_ = 0;
            end_of_window_ += window_ * periods;
        }

        auto prevwin_weight = 1.0 * (end_of_window_ - now) / window_;
        auto currwin_space = limit_ - currwin_amount_ - (prevwin_amount_ * prevwin_weight);
#ifdef RATE_LIMITR_VERBOSE
        printf(
            " *** [sliding_window_counter] prevwin_weight=%f, currwin_space=%f, quantity=%ld ***\n",
            prevwin_weight, currwin_space, quantity);
#endif
        if (quantity > (int64_t)std::ceil(currwin_space)) {
            return false;
        }

        currwin_amount_ += quantity;
        return true;
    }

  private:
    uint64_t currwin_amount_;
    uint64_t prevwin_amount_;
    std::chrono::steady_clock::time_point end_of_window_;
};

}  // namespace tbd

#endif
