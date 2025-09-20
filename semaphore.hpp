#ifndef SEMAPHORE_HPP_
#define SEMAPHORE_HPP_

#include <errno.h>
#include <semaphore.h>

#include <chrono>
#include <memory>
#include <system_error>

namespace tbd {

class semaphore
{
  public:
    explicit semaphore(int value = 1)
        : sem_(std::make_unique<sem_t>())
    {
        if (::sem_init(sem_.get(), 0, value) < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    semaphore(const semaphore&) = delete;
    semaphore& operator=(const semaphore&) = delete;
    semaphore(semaphore&& rhs) noexcept
        : sem_(std::move(rhs.sem_))
    {
    }
    semaphore& operator=(semaphore&& rhs) noexcept
    {
        if (this != &rhs) {
            sem_ = std::move(rhs.sem_);
        }
        return *this;
    }

    ~semaphore() noexcept
    {
        if (sem_) {
            ::sem_destroy(sem_.get());
        }
    }

    void release() const
    {
        if (::sem_post(sem_.get()) < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    void acquire() const
    {
        if (::sem_wait(sem_.get()) < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    bool try_acquire(long timeout_ms = 0) const
    {
        if (timeout_ms == 0) {
            int ret = ::sem_trywait(sem_.get());
            if (ret == 0) {
                return true;
            }
            if (ret < 0 && errno == EAGAIN) {
                return false;
            }

        } else {
            using namespace std::chrono;
            auto abs_nsec = duration_cast<nanoseconds>(
                                (system_clock::now() + milliseconds(timeout_ms)).time_since_epoch())
                                .count();
            struct timespec abs_timeout;
            abs_timeout.tv_sec = abs_nsec / (1000L * 1000 * 1000);
            abs_timeout.tv_nsec = abs_nsec % (1000L * 1000 * 1000);
            int ret = ::sem_timedwait(sem_.get(), &abs_timeout);
            if (ret == 0) {
                return true;
            }
            if (ret < 0 && errno == ETIMEDOUT) {
                return false;
            }
        }

        throw std::system_error(errno, std::generic_category());
    }

  private:
    std::unique_ptr<sem_t> sem_;
};

class parker
{
  public:
    parker()
        : sem_(0)
    {
    }

    void park() const
    {
        sem_.acquire();
    }

    void unpark() const
    {
        sem_.release();
    }

  private:
    semaphore sem_;
};

}  // namespace tbd

#endif
