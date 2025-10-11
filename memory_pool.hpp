#ifndef MEMORY_POOL_
#define MEMORY_POOL_

#include <atomic>
#include <cassert>
#include <mutex>
#include <vector>

namespace tbd {

namespace detail {
template <typename T>
class memory_pool_base
{
  public:
    memory_pool_base(const memory_pool_base&) = delete;
    memory_pool_base& operator=(const memory_pool_base&) = delete;
    memory_pool_base(memory_pool_base&&) noexcept = default;
    memory_pool_base& operator=(memory_pool_base&& rhs) noexcept = default;
    virtual ~memory_pool_base() noexcept = default;
    virtual void* acquire() = 0;
    virtual void release(void* p) = 0;

  protected:
    // align of 8
    static constexpr size_t ALIGN = 8U;
    static constexpr size_t WORDSZ = sizeof(uint64_t) * 8;

    size_t block_size_;
    std::vector<uint8_t> pool_;
    std::vector<T> avail_map_;

    memory_pool_base(size_t blksz, size_t count)
        : block_size_((blksz + ALIGN - 1) & ~(ALIGN - 1))
        , pool_(block_size_ * count)
        , avail_map_((count + (WORDSZ - 1)) / WORDSZ)
    {
        for (size_t i = 0; i < avail_map_.size(); ++i) {
            avail_map_[i] = 0xffffffffffffffffULL;
        }
        if (auto rem = count % WORDSZ) {
            avail_map_.back() = (1ULL << rem) - 1;
        }
    }

    std::pair<size_t, uint64_t> index_relbit(void* ptr) const
    {
        if (!ptr) {
            return {0, 0};
        }

        if (ptr < pool_.data() || ptr >= pool_.data() + pool_.size()) {
            throw std::system_error(EINVAL, std::generic_category());
        }

        auto idx = ((uint8_t*)ptr - pool_.data()) / block_size_;
        return {idx / WORDSZ, 1ULL << (idx & (WORDSZ - 1))};
    }
};
}  // namespace detail

class memory_pool : public detail::memory_pool_base<uint64_t>
{
  public:
    memory_pool(size_t blksz, size_t count)
        : detail::memory_pool_base<uint64_t>(blksz, count)
    {
    }

    void* acquire() override
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);

        for (size_t i = 0; i < avail_map_.size(); ++i) {
            if (avail_map_[i]) {
                auto pos = __builtin_ffsll(avail_map_[i]) - 1;
                avail_map_[i] &= ~(1ULL << pos);
                auto ptr = pool_.data() + block_size_ * (i * WORDSZ + pos);
                assert(ptr < pool_.data() + pool_.size());
                return ptr;
            }
        }
        return nullptr;
    }

    void release(void* ptr) override
    {
        auto [index, relbit] = index_relbit(ptr);
        if (relbit) {
            std::lock_guard<decltype(mtx_)> lk(mtx_);
            avail_map_[index] |= relbit;
        }
    }

  private:
    std::mutex mtx_;
};

class memory_pool_lf : public detail::memory_pool_base<std::atomic<uint64_t>>
{
  public:
    memory_pool_lf(size_t blksz, size_t count)
        : detail::memory_pool_base<std::atomic<uint64_t>>(blksz, count)
    {
    }

    void* acquire() override
    {
        for (size_t i = 0; i < avail_map_.size(); ++i) {
            auto old_val = avail_map_[i].load(std::memory_order_relaxed);
            while (old_val) {
                auto pos = __builtin_ffsll(old_val) - 1;
                if (avail_map_[i].compare_exchange_weak(old_val, old_val & ~(1ULL << pos),
                                                        std::memory_order_acquire,
                                                        std::memory_order_relaxed)) {
                    return pool_.data() + block_size_ * (i * WORDSZ + pos);
                }
            }
        }
        return nullptr;
    }

    void release(void* ptr) override
    {
        auto [index, relbit] = index_relbit(ptr);
        if (relbit) {
            avail_map_[index] |= relbit;
        }
    }
};

}  // namespace tbd

#endif
