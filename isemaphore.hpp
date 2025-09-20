#ifndef ISEMAPHORE_HPP_
#define ISEMAPHORE_HPP_

// #define NDEBUG
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>

namespace tbd {

// indexed-semaphore
class isemaphore
{
    static constexpr size_t SEM_VALUE_MAX = 64UL * 64UL;

  public:
    explicit isemaphore(size_t count)
    {
        if (count > SEM_VALUE_MAX) {
            throw std::length_error("isemaphore: count too large");
        }

        nmaps_ = count >> 6;       // count / 64 => 0 ~ 63
        auto rem = count & 0x3fU;  // count % 64 => 0 ~ 63
        if (rem > 0) {
            ++nmaps_;
        }
        availables_ = std::make_unique<uint64_t[]>(nmaps_);
        for (size_t i = 0; i < nmaps_; ++i) {
            availables_[i] = 0xffffffffffffffffULL;
        }
        if (rem > 0) {
            availables_[nmaps_ - 1] = (rem == 64) ? 0xffffffffffffffffULL : ((1ULL << rem) - 1);
        }
        indirects_ = (nmaps_ == 64) ? 0xffffffffffffffffULL : (1ULL << nmaps_) - 1;
    }

    ~isemaphore(void) noexcept = default;

    /**
     * wait_ms > 0: => wait specified milliseconds
     * wait_ms = 0: => return immediately
     * wait_ms < 0: => wait indefinitely
     */
    int64_t acquire(int wait_ms = -1)
    {
        std::unique_lock<std::mutex> lk(mtx_);
        auto map = __builtin_ffsll(indirects_);
        if (map == 0) {  // no avail
            if (wait_ms == 0) {
                return -1;

            } else if (wait_ms < 0) {
                cv_.wait(lk, [this] { return indirects_ > 0; });

            } else {
                bool ok = cv_.wait_for(lk, std::chrono::milliseconds(wait_ms),
                                       [this] { return indirects_ > 0; });
                if (!ok) {
                    return -1;
                }
            }
            map = __builtin_ffsll(indirects_);
            assert(map != 0);
        }

        --map;
        auto avail = __builtin_ffsll(availables_[map]);
        assert(avail != 0);
        --avail;
        auto pos = 64 * map + avail;
        availables_[map] &= ~(1UL << avail);
        if (availables_[map] == 0) {
            indirects_ &= ~(1UL << map);
        }

        return pos;
    }

    void release(int64_t pos)
    {
        if (pos >= (int64_t)SEM_VALUE_MAX || pos < 0) {
            throw std::invalid_argument("isemaphore::release: invalid position");
        }

        std::lock_guard<std::mutex> lk(mtx_);
        auto quot = pos >> 6;
        auto rem = pos & 0x3fU;
        availables_[quot] |= (1ULL << rem);
        indirects_ |= (1ULL << quot);
        cv_.notify_one();
    }

  private:
    size_t nmaps_ = 0;
    std::unique_ptr<uint64_t[]> availables_;
    uint64_t indirects_;
    std::mutex mtx_;
    std::condition_variable cv_;
};

}  // namespace tbd

#endif
