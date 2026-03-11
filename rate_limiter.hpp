#ifndef RATE_LIMITER_HPP_
#define RATE_LIMITER_HPP_

#include <cassert>
#include <chrono>
#include <cmath>
#ifdef RATE_LIMITER_VERBOSE
#include <cstdio>
#endif
#include <deque>
#include <stdexcept>
#include <thread>

namespace tbd {

/****************************************************************************
 * Base Class
 */
class rate_limiter
{
  public:
    virtual ~rate_limiter() noexcept = default;
    virtual std::pair<bool, std::chrono::nanoseconds> try_request(int64_t quantity) = 0;
    void request(int64_t quantity)
    {
        auto [ok, retry_after] = try_request(quantity);
        if (!ok) {
#ifdef RATE_LIMITER_VERBOSE
            printf(" *** [rate_limiter] cannot process request! wait for %lu ms ***\n",
                   retry_after.count() / (1000 * 1000));
#endif
            std::this_thread::sleep_for(retry_after);
            postprocess(quantity);
        }
    }

  protected:
    uint64_t limit_;
    std::chrono::nanoseconds window_;

    template <typename Duration>
    rate_limiter(uint64_t limit, Duration window)
        : limit_(limit)
        , window_(window)
    {
    }

    void assert_request(int64_t quantity)
    {
        if (quantity < 0 || (uint64_t)quantity > limit_) {
            throw std::invalid_argument("request over limit");
        }
    }

    virtual void postprocess(int64_t) = 0;
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

    std::pair<bool, std::chrono::nanoseconds> try_request(int64_t quantity) override
    {
        assert_request(quantity);
        auto now = std::chrono::steady_clock::now();
        auto elapsed = now - last_requested_;
        auto refills = 1.0 * elapsed.count() * limit_ / window_.count();
        tokens_left_ = std::min(tokens_left_ + refills, (double)limit_);
        last_requested_ = now;
#ifdef RATE_LIMITER_VERBOSE
        printf(" *** [token_bucket] elapsed=%lu ms, refills=%.02f, tokens_left_=%.02f,"
               " quantity=%ld ***\n",
               std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), refills,
               tokens_left_, quantity);
#endif

        if (quantity <= tokens_left_) {
            tokens_left_ -= quantity;
            return {true, std::chrono::nanoseconds{0}};
        }

        auto wait = (quantity - tokens_left_) * window_.count() / limit_;
        return {false, std::chrono::nanoseconds((uint64_t)std::ceil(wait))};
    }

  private:
    double tokens_left_;
    std::chrono::steady_clock::time_point last_requested_{};

    void postprocess(int64_t) noexcept override
    {
        tokens_left_ = 0;
        last_requested_ = std::chrono::steady_clock::now();
    }
};

/****************************************************************************
 * GCRA (Generic Cell Rate Algorithm)
 */
class gcra : public rate_limiter
{
  public:
    template <typename Duration>
    gcra(uint64_t limit, Duration window)
        : rate_limiter(limit, window)
    {
    }

    std::pair<bool, std::chrono::nanoseconds> try_request(int64_t quantity) override
    {
        assert_request(quantity);
        auto now = std::chrono::steady_clock::now();
#ifdef RATE_LIMITER_VERBOSE
        printf(
            " *** [gcra] now=%lu, tat_=%lu, window=%lu ***\n",
            std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count(),
            std::chrono::duration_cast<std::chrono::nanoseconds>(tat_.time_since_epoch()).count(),
            window_.count());
#endif
        if (now >= tat_ - window_) {
            tat_ = std::max(now, tat_) + quantity * window_ / limit_;
            return {true, std::chrono::nanoseconds(0)};
        }

        return {false, tat_ - window_ - now};
    }

  private:
    std::chrono::steady_clock::time_point tat_{};

    void postprocess(int64_t quantity) noexcept override
    {
        tat_ = std::max(std::chrono::steady_clock::now(), tat_) + quantity * window_ / limit_;
    }
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

    std::pair<bool, std::chrono::nanoseconds> try_request(int64_t quantity) override
    {
        assert_request(quantity);
#ifdef RATE_LIMITER_VERBOSE
        auto log_before = log_.size();
#endif
        auto now = std::chrono::steady_clock::now();
        auto beginning_of_window = now - window_;
        while (!log_.empty() && log_.front().arrived_at < beginning_of_window) {
            amount_in_window_ -= log_.front().quantity;
            log_.pop_front();
        }

#ifdef RATE_LIMITER_VERBOSE
        printf(" *** [sliding_window_log] erased=%lu, logsz=%lu, amount_in_window_=%lu,"
               " quantity=%ld ***\n",
               log_before - log_.size(), log_.size(), amount_in_window_, quantity);
#endif
        auto balance = (int64_t)limit_ - amount_in_window_ - quantity;
        if (balance >= 0) {
            log_.emplace_back(log_entry{now, (uint64_t)quantity});
            amount_in_window_ += quantity;
            return {true, std::chrono::nanoseconds{0}};
        }

        int64_t should_pop = 0;
        for (const auto& e : log_) {
            should_pop += e.quantity;
            if (should_pop >= (-balance)) {
                return {false, e.arrived_at + window_ - now};
            }
        }
        assert(false);
    }

  private:
    struct log_entry
    {
        std::chrono::steady_clock::time_point arrived_at;
        uint64_t quantity;
    };

    int64_t amount_in_window_;
    std::deque<log_entry> log_;  // (head) old <-> new (tail)

    void postprocess(int64_t quantity) override
    {
        log_.emplace_back(log_entry{std::chrono::steady_clock::now(), (uint64_t)quantity});
        amount_in_window_ += quantity;
    }
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
        , prevwin_amount_(limit_)
        , end_of_window_(std::chrono::steady_clock::now() + window_)
    {
    }

    std::pair<bool, std::chrono::nanoseconds> try_request(int64_t quantity) override
    {
        assert_request(quantity);
        auto [periods, now] = elapsed_periods();
        slide_window(periods);

        auto prevwin_weight = 1.0 * (end_of_window_ - now) / window_;
        auto amount_in_window = currwin_amount_ + (prevwin_amount_ * prevwin_weight);
        auto balance = limit_ - amount_in_window - quantity;
#ifdef RATE_LIMITER_VERBOSE
        printf(" *** [sliding_window_counter] prevwin_amount_=%lu, prevwin_weight=%.2f,"
               " currwin_amount_=%lu, amount_in_window=%.2f, quantity=%ld ***\n",
               prevwin_amount_, prevwin_weight, currwin_amount_, amount_in_window, quantity);
#endif

        if (balance >= 0) {
            currwin_amount_ += quantity;
            return {true, std::chrono::nanoseconds{0}};
        }

        auto retry_after = (uint64_t)std::ceil(-balance * window_.count() / limit_);
        return {false, std::chrono::nanoseconds{retry_after}};
    }

  private:
    uint64_t currwin_amount_;
    uint64_t prevwin_amount_;
    std::chrono::steady_clock::time_point end_of_window_;

    std::pair<uint64_t, std::chrono::steady_clock::time_point> elapsed_periods() noexcept
    {
        auto now = std::chrono::steady_clock::now();
        return {(now < end_of_window_) ? 0 : 1 + (now - end_of_window_).count() / window_.count(),
                now};
    }

    void slide_window(uint64_t periods) noexcept
    {
        if (periods > 0) {
            prevwin_amount_ = (periods == 1) ? currwin_amount_ : 0;
            currwin_amount_ = 0;
            end_of_window_ += window_ * periods;
        }
    }

    void postprocess(int64_t quantity) noexcept override
    {
        auto [periods, _] = elapsed_periods();
        assert(periods <= 1);
        slide_window(periods);
        currwin_amount_ += quantity;
    }
};

}  // namespace tbd

#endif
