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
    std::shared_ptr<M> mtx_;

    void assert_mutex_alive() const
    {
        if (!mtx_) {
            throw std::runtime_error("mutex_wrap: already moved away");
        }
    }

    class guard
    {
        T* data_;
        std::weak_ptr<M> mtx_;

        guard(T* d, std::shared_ptr<M>& m)
            : data_(d)
            , mtx_(m)
        {
        }
        friend class mutex_wrap<T, M>;

        void assert_mutex_alive() const
        {
            if (mtx_.expired()) {
                throw std::runtime_error("mutex_wrap: already moved away");
            }
        }

      public:
        guard(const guard&) = delete;
        guard& operator=(const guard&) = delete;
        guard(guard&&) noexcept = default;
        guard& operator=(guard&&) noexcept = delete;

        ~guard()
        {
            if (auto sp = mtx_.lock()) {
                sp->unlock();
            }
        };

        T* get() const
        {
            assert_mutex_alive();
            return data_;
        }

        T* operator->() const
        {
            return get();
        }

        T& operator*() const
        {
            assert_mutex_alive();
            return *data_;
        }
    };

    static guard make_guard(T* d, std::shared_ptr<M>& m)
    {
        return guard(d, m);
    }

  public:
    mutex_wrap(T&& data)
        : data_(std::forward<T>(data))
        , mtx_(std::make_shared<M>())
    {
    }

    mutex_wrap(const mutex_wrap&) = delete;
    mutex_wrap& operator=(const mutex_wrap&) = delete;

    virtual ~mutex_wrap() noexcept = default;

    [[nodiscard]] guard lock()
    {
        assert_mutex_alive();
        mtx_->lock();
        return guard(&data_, mtx_);
    }

    template <typename F, typename = std::enable_if_t<std::is_invocable_v<F, T&>>>
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
  public:
    rwlock_wrap(T&& data)
        : mutex_wrap<T, std::shared_mutex>(std::move(data))
    {
    }

    [[nodiscard]] typename mutex_wrap<T, std::shared_mutex>::guard lock_shared()
    {
        this->assert_mutex_alive();
        this->mtx_->lock_shared();
        return this->make_guard(&this->data_, this->mtx_);
    }

    template <typename F, typename = std::enable_if_t<std::is_invocable_v<F, const T&>>>
    void lock_shared(F&& fn)
    {
        this->assert_mutex_alive();
        std::shared_lock<std::shared_mutex> lk(*this->mtx_);
        fn(this->data_);
    }
};

}  // namespace tbd

#endif
