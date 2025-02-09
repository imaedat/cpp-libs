#ifndef MUTEX_WRAP_HPP_
#define MUTEX_WRAP_HPP_

#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>

namespace tbd {

template <typename T>
class mutex_wrap
{
    using Deleter = std::function<void(T*)>;

  public:
    /* explicit */ mutex_wrap(T&& data)
        : data_(std::move(data))
        , mtx_(std::make_unique<mtxtype>())
    {}

    std::unique_ptr<T, Deleter> lock()
    {
        if (!mtx_) {
            throw std::runtime_error("mutex_wrap: already moved away");
        }

        mtx_->lock();
        return std::unique_ptr<T, Deleter>(&data_, [this](T* p) {
            (void)p;
            mtx_->unlock();
        });
    }

  private:
    T data_;
    std::unique_ptr<std::mutex> mtx_;
    using mtxtype = typename std::decay<decltype(*mtx_)>::type;
};

}  // namespace tbd

#endif
