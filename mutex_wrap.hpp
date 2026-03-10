#ifndef MUTEX_WRAP_HPP_
#define MUTEX_WRAP_HPP_

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <type_traits>

namespace tbd {

template <typename T, typename M = std::mutex>
class mutex_wrap
{
  protected:
    /************************************************************************
     * pin
     */
    struct pin
    {
        T data_;
        M mtx_;

        template <typename... Args>
        pin(Args&&... args)
            : data_(std::forward<Args>(args)...)
        {
        }
    };

    using pin_t = mutex_wrap<T, M>::pin;

    /************************************************************************
     * guard
     */
    template <bool LockShared = false>
    class [[nodiscard]] guard
    {
        pin_t* pin_ = nullptr;

        guard(std::unique_ptr<pin_t>& p)
            : pin_(p.get())
        {
        }

        void assert_mutex_alive() const
        {
            if (!pin_) {
                throw std::runtime_error("mutex_wrap: already moved away");
            }
        }

        void unlock()
        {
            if (pin_) {
                if constexpr (LockShared) {
                    pin_->mtx_.unlock_shared();
                } else {
                    pin_->mtx_.unlock();
                }
            }
        }

      public:
        guard(const guard&) = delete;
        guard& operator=(const guard&) = delete;
        guard(guard&& rhs) noexcept
            : pin_(std::exchange(rhs.pin_, nullptr))
        {
        }
        guard& operator=(guard&& rhs) noexcept
        {
            if (this != &rhs) {
                unlock();
                pin_ = std::exchange(rhs.pin_, nullptr);
            }
            return *this;
        }

        ~guard()
        {
            unlock();
        };

        auto get() const
        {
            assert_mutex_alive();
            if constexpr (LockShared) {
                return const_cast<const T*>(&pin_->data_);
            } else {
                return &pin_->data_;
            }
        }

        auto operator->() const
        {
            return get();
        }

        auto& operator*() const
        {
            return *get();
        }

        friend class mutex_wrap<T, M>;
    };

    template <bool LockShared = false>
    static guard<LockShared> make_guard(std::unique_ptr<pin_t>& p)
    {
        return guard<LockShared>(p);
    }

    /************************************************************************
     * mutex_wrap
     */
    std::unique_ptr<pin> pin_ = nullptr;

    void assert_mutex_alive() const
    {
        if (!pin_) {
            throw std::runtime_error("mutex_wrap: already moved away");
        }
    }

  public:
    template <typename... Args,
              std::enable_if_t<(... && !std::is_same_v<std::decay_t<Args>, mutex_wrap<T, M>>),
                               bool> = true>
    mutex_wrap(Args&&... args)
        : pin_(std::make_unique<pin>(std::forward<Args>(args)...))
    {
    }

    explicit mutex_wrap(T&& data)
        : pin_(std::make_unique<pin>(std::forward<T>(data)))
    {
    }

    mutex_wrap(const mutex_wrap&) = delete;
    mutex_wrap& operator=(const mutex_wrap&) = delete;
    mutex_wrap(mutex_wrap&&) noexcept = default;
    mutex_wrap& operator=(mutex_wrap&&) noexcept = default;

    virtual ~mutex_wrap() noexcept = default;

    [[nodiscard]] guard<> lock() &
    {
        assert_mutex_alive();
        pin_->mtx_.lock();
        return guard<>(pin_);
    }

    guard<> lock() && = delete;

    template <typename F, std::enable_if_t<std::is_invocable_v<F, T&>, bool> = true>
    void lock(F&& fn)
    {
        assert_mutex_alive();
        std::lock_guard<M> lk(pin_->mtx_);
        fn(pin_->data_);
    }

    M& native_mutex() &
    {
        assert_mutex_alive();
        return pin_->mtx_;
    }

    M& native_mutex() && = delete;
};

template <typename T>
class rwlock_wrap : public mutex_wrap<T, std::shared_mutex>
{
    using M = std::shared_mutex;
    using shared_guard = typename mutex_wrap<T, M>::template guard<true>;

  public:
    template <
        typename... Args,
        std::enable_if_t<(... && !std::is_same_v<std::decay_t<Args>, rwlock_wrap<T>>), bool> = true>
    rwlock_wrap(Args&&... args)
        : mutex_wrap<T, M>(std::forward<Args>(args)...)
    {
    }

    explicit rwlock_wrap(T&& data)
        : mutex_wrap<T, M>(std::forward<T>(data))
    {
    }

    [[nodiscard]] shared_guard lock_shared() &
    {
        this->assert_mutex_alive();
        this->pin_->mtx_.lock_shared();
        return this->template make_guard<true>(this->pin_);
    }

    shared_guard lock_shared() && = delete;

    template <typename F, std::enable_if_t<std::is_invocable_v<F, const T&>, bool> = true>
    void lock_shared(F&& fn)
    {
        this->assert_mutex_alive();
        std::shared_lock<M> lk(this->pin_->mtx_);
        fn(this->pin_->data_);
    }
};

}  // namespace tbd

#endif
