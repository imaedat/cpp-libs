#ifndef MUTEX_WRAP_HPP_
#define MUTEX_WRAP_HPP_

#include <functional>
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
    T data_;
    std::unique_ptr<M> mtx_;
    using Deleter = std::function<void(T*)>;

    void assert_mutex_alive() const
    {
        if (!mtx_) {
            throw std::runtime_error("mutex_wrap: already moved away");
        }
    }

  public:
    mutex_wrap(T&& data)
        : data_(std::move(data))
        , mtx_(std::make_unique<M>())
    {
    }

    virtual ~mutex_wrap() = default;

    std::unique_ptr<T, Deleter> lock()
    {
        assert_mutex_alive();

        mtx_->lock();
        return std::unique_ptr<T, Deleter>(&data_, [this](T* p) {
            (void)p;
            mtx_->unlock();
        });
    }

    template <typename F, std::enable_if_t<std::is_invocable_v<F, T&>, std::nullptr_t> = nullptr>
    void lock(F&& fn)
    {
        assert_mutex_alive();

        std::lock_guard<M> lk(*mtx_);
        fn(data_);
    }

    M& operator*() const noexcept
    {
        return *mtx_;
    }
};

template <typename T>
class rwlock_wrap : public mutex_wrap<T, std::shared_mutex>
{
    using Deleter = typename mutex_wrap<T, std::shared_mutex>::Deleter;

  public:
    rwlock_wrap(T&& data)
        : mutex_wrap<T, std::shared_mutex>(std::move(data))
    {
    }

    std::unique_ptr<T, Deleter> lock_shared()
    {
        this->assert_mutex_alive();

        this->mtx_->lock_shared();
        return std::unique_ptr<T, Deleter>(&this->data_, [this](T* p) {
            (void)p;
            this->mtx_->unlock_shared();
        });
    }

    template <typename F, std::enable_if_t<std::is_invocable_v<F, T&>, std::nullptr_t> = nullptr>
    void lock_shared(F&& fn)
    {
        this->assert_mutex_alive();

        std::shared_lock<std::shared_mutex> lk(*this->mtx_);
        fn(this->data_);
    }
};

}  // namespace tbd

#endif
