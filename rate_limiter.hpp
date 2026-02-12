#ifndef RATE_LIMITER_HPP_
#define RATE_LIMITER_HPP_

#include <cassert>
#include <chrono>
#include <cmath>
#ifdef RATE_LIMITER_VERBOSE
#include <cstdio>
#endif
#include <deque>
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
    virtual void request(int64_t quantity) = 0;

  protected:
    uint64_t limit_;
    std::chrono::nanoseconds window_;
    double rate_;

    template <typename Duration>
    rate_limiter(uint64_t limit, Duration window)
        : limit_(limit)
        , window_(window)
        , rate_(1.0 * limit_ / window_.count())
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

    std::pair<bool, std::chrono::nanoseconds> try_request(int64_t quantity) override
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = now - last_requested_;

        unsigned refills = 0;
        if (elapsed >= window_) {
            tokens_left_ = limit_;
        } else {
            refills = (unsigned)std::round((limit_ * elapsed) / window_);
            tokens_left_ = std::min(tokens_left_ + refills, limit_);
        }
        last_requested_ = now;
#ifdef RATE_LIMITER_VERBOSE
        printf(" *** [token_bucket] elapsed=%lu ms, refills=%u, tokens_left_=%lu,"
               " quantity=%ld ***\n",
               std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), refills,
               tokens_left_, quantity);
#endif

        if (quantity <= (int64_t)tokens_left_) {
            tokens_left_ -= quantity;
            return {true, std::chrono::nanoseconds{0}};
        }

        return {false, (quantity - tokens_left_) * window_ / limit_};
    }

    void request(int64_t quantity) override
    {
        auto [ok, wait_ns] = try_request(quantity);
        if (!ok) {
#ifdef RATE_LIMITER_VERBOSE
            printf(" *** [token_bucket] not enough tokens! wait for %lu ms ***\n",
                   wait_ns.count() / (1000 * 1000));
#endif
            std::this_thread::sleep_for(wait_ns);
            tokens_left_ = 0;
            last_requested_ = std::chrono::steady_clock::now();
        }
    }

  private:
    uint64_t tokens_left_;
    std::chrono::steady_clock::time_point last_requested_{};
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
#ifdef RATE_LIMITER_VERBOSE
        auto before = log_.size();
#endif
        auto now = std::chrono::steady_clock::now();
        auto beginning_of_window = now - window_;
        while (!log_.empty() && log_.front().arrived_at < beginning_of_window) {
            amount_in_window_ -= log_.front().quantity;
            log_.pop_front();
        }

#ifdef RATE_LIMITER_VERBOSE
        auto logsz = log_.size();
        auto erased = before - logsz;
        printf(" *** [sliding_window_log] erased=%lu, logsz=%lu, amount_in_window_=%lu,"
               " quantity=%ld ***\n",
               erased, logsz, amount_in_window_, quantity);
#endif
        auto balance = (int64_t)limit_ - amount_in_window_ - quantity;
        if (balance >= 0) {
            log_.emplace_back(log_entry{now, (uint64_t)quantity});
            amount_in_window_ += quantity;
            return {true, std::chrono::nanoseconds{0}};
        }

        return {false, -balance * window_ / limit_};
    }

    void request(int64_t quantity) override
    {
        auto [ok, wait_ns] = try_request(quantity);
        if (!ok) {

#ifdef RATE_LIMITER_VERBOSE
            printf(" *** [sliding_window_log] window amount over! wait for %lu ms ***\n",
                   wait_ns.count() / (1000 * 1000));
#endif
            std::this_thread::sleep_for(wait_ns);
            log_.emplace_back(log_entry{std::chrono::steady_clock::now(), (uint64_t)quantity});
            amount_in_window_ += quantity;
        }
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
        , prevwin_amount_(limit_)
        , end_of_window_(std::chrono::steady_clock::now() + window_)
    {
    }

    std::pair<bool, std::chrono::nanoseconds> try_request(int64_t quantity) override
    {
        auto [periods, now] = elapsed_periods();
        if (periods > 0) {
            prevwin_amount_ = (periods == 1) ? currwin_amount_ : 0;
            currwin_amount_ = 0;
            end_of_window_ += window_ * periods;
        }

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

        auto wait_ns = (uint64_t)std::round(-balance * window_.count() / limit_);
        return {false, std::chrono::nanoseconds{wait_ns}};
    }

    void request(int64_t quantity) override
    {
        auto [ok, wait_ns] = try_request(quantity);
        if (!ok) {
#ifdef RATE_LIMITER_VERBOSE
            printf(" *** [sliding_window_counter] not enough space! wait for %lu ms ***\n",
                   wait_ns.count() / (1000 * 1000));
#endif
            std::this_thread::sleep_for(wait_ns);

            auto [periods, _] = elapsed_periods();
            if (periods > 0) {
                for (auto i = 0U; i < periods; ++i) {
                    int64_t currwin_space = limit_ - (int64_t)currwin_amount_;
                    if (currwin_space >= quantity) {
                        currwin_amount_ += quantity;
                        quantity = 0;
                    } else {
                        quantity -= currwin_space;
                        currwin_amount_ = limit_;
                    }
                    prevwin_amount_ = currwin_amount_;
                    currwin_amount_ = 0;
                    end_of_window_ += window_;
                }
            }
            currwin_amount_ += quantity;
        }
    }

  private:
    uint64_t currwin_amount_;
    uint64_t prevwin_amount_;
    std::chrono::steady_clock::time_point end_of_window_;

    std::pair<uint64_t, std::chrono::steady_clock::time_point> elapsed_periods() noexcept
    {
        auto now = std::chrono::steady_clock::now();
        if (now < end_of_window_) {
            return {0, now};
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(now - end_of_window_);
        return {1 + elapsed.count() / window_.count(), now};
    }
};

}  // namespace tbd

#endif
