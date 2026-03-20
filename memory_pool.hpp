#ifndef MEMORY_POOL_
#define MEMORY_POOL_

#include <atomic>
#include <cassert>
#include <cstddef>
#include <memory>
#include <mutex>
#include <vector>

namespace tbd {

namespace detail {
template <typename T, size_t AlignAs = alignof(std::max_align_t)>
class memory_pool_base
{
    static constexpr size_t ceil2ll(size_t n)
    {
        return (n <= 1) ? 1 : size_t(1) << (sizeof(size_t) * 8 - __builtin_clzll(n - 1));
    }

  public:
    memory_pool_base(const memory_pool_base&) = delete;
    memory_pool_base& operator=(const memory_pool_base&) = delete;
    memory_pool_base(memory_pool_base&&) noexcept = default;
    memory_pool_base& operator=(memory_pool_base&& rhs) noexcept = default;
    virtual ~memory_pool_base() noexcept = default;

  protected:
    static constexpr size_t ALIGN_AS = ceil2ll(AlignAs);
    static constexpr size_t WORD_BITS = sizeof(uint64_t) * 8;
    struct aligned_deleter
    {
        void operator()(void* p) const noexcept
        {
            ::operator delete (p, std::align_val_t{ALIGN_AS});
        }
    };

    size_t block_size_ = 0;
    size_t pool_size_ = 0;
    std::unique_ptr<std::byte, aligned_deleter> pool_;
    std::vector<T> avail_map_;

    memory_pool_base(size_t blksz, size_t count)
        : block_size_((blksz + ALIGN_AS - 1) & ~(ALIGN_AS - 1))
        , pool_size_(block_size_ * count)
        , pool_((std::byte*)::operator new (pool_size_, std::align_val_t{ALIGN_AS}),
                aligned_deleter{})
        , avail_map_((count + (WORD_BITS - 1)) / WORD_BITS)
    {
        for (size_t i = 0; i < avail_map_.size(); ++i) {
            avail_map_[i] = 0xffffffffffffffffULL;
        }
        if (auto rem = count % WORD_BITS) {
            avail_map_.back() = (1ULL << rem) - 1;
        }
    }

    std::pair<size_t, uint64_t> index_relbit(void* ptr) const
    {
        if (!ptr) {
            return {0, 0};
        }

        if (ptr < pool_.get() || ptr >= pool_.get() + pool_size_) {
            throw std::out_of_range("index_relbit: invalid pointer");
        }

        auto idx = ((std::byte*)ptr - pool_.get()) / block_size_;
        return {idx / WORD_BITS, 1ULL << (idx & (WORD_BITS - 1))};
    }
};
}  // namespace detail

template <size_t AlignAs = alignof(std::max_align_t)>
class memory_pool : public detail::memory_pool_base<uint64_t, AlignAs>
{
  public:
    memory_pool(size_t blksz, size_t count)
        : detail::memory_pool_base<uint64_t, AlignAs>(blksz, count)
    {
    }

    void* acquire()
    {
        std::lock_guard lk(mtx_);
        for (size_t i = 0; i < this->avail_map_.size(); ++i) {
            if (this->avail_map_[i]) {
                auto pos = __builtin_ffsll(this->avail_map_[i]) - 1;
                this->avail_map_[i] &= ~(1ULL << pos);
                auto ptr = this->pool_.get() + this->block_size_ * (i * this->WORD_BITS + pos);
                assert(ptr < this->pool_.get() + this->pool_size_);
                return ptr;
            }
        }
        return nullptr;
    }

    void release(void* ptr)
    {
        auto [index, relbit] = this->index_relbit(ptr);
        if (relbit) {
            std::lock_guard lk(mtx_);
            assert(!(this->avail_map_[index] & relbit));
            this->avail_map_[index] |= relbit;
        }
    }

  private:
    std::mutex mtx_;
};

template <size_t AlignAs = alignof(std::max_align_t)>
class memory_pool_lf : public detail::memory_pool_base<std::atomic<uint64_t>, AlignAs>
{
  public:
    memory_pool_lf(size_t blksz, size_t count)
        : detail::memory_pool_base<std::atomic<uint64_t>, AlignAs>(blksz, count)
    {
    }
    memory_pool_lf(memory_pool_lf&& rhs)
        : detail::memory_pool_base<std::atomic<uint64_t>, AlignAs>(std::move(rhs))
        , hint_(rhs.hint_.load(std::memory_order_relaxed))
    {
    }
    memory_pool_lf& operator=(memory_pool_lf&& rhs)
    {
        if (this != &rhs) {
            detail::memory_pool_base<std::atomic<uint64_t>, AlignAs>::operator=(std::move(rhs));
            hint_.store(rhs.hint_.load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        return *this;
    }

    void* acquire()
    {
        auto i = hint_.load(std::memory_order_relaxed);
        for (; i < this->avail_map_.size(); ++i) {
            auto old_val = this->avail_map_[i].load(std::memory_order_relaxed);
            while (old_val) {
                auto pos = __builtin_ffsll(old_val) - 1;
                if (this->avail_map_[i].compare_exchange_weak(old_val, old_val & ~(1ULL << pos),
                                                              std::memory_order_acq_rel,
                                                              std::memory_order_relaxed)) {
                    hint_.store(i, std::memory_order_relaxed);
                    auto ptr = this->pool_.get() + this->block_size_ * (i * this->WORD_BITS + pos);
                    assert(ptr < this->pool_.get() + this->pool_size_);
                    return ptr;
                }
            }
        }
        return nullptr;
    }

    void release(void* ptr)
    {
        auto [index, relbit] = this->index_relbit(ptr);
        if (relbit) {
            auto old_val = this->avail_map_[index].fetch_or(relbit, std::memory_order_release);
            assert(!(old_val & relbit));
            if (index < hint_.load(std::memory_order_relaxed)) {
                hint_.store(index, std::memory_order_relaxed);
            }
        }
    }

  private:
    std::atomic<size_t> hint_{0};
};

}  // namespace tbd

#endif
