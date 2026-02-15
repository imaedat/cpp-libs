#ifndef SEMAPHORE_HPP_
#define SEMAPHORE_HPP_

#include <errno.h>
#include <semaphore.h>

#include <atomic>
#include <chrono>
#include <cmath>
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
    semaphore(semaphore&&) noexcept = default;
    semaphore& operator=(semaphore&&) noexcept = default;

    ~semaphore() noexcept
    {
        if (sem_) {
            ::sem_destroy(sem_.get());
        }
    }

    void release()
    {
        if (::sem_post(sem_.get()) < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    void acquire()
    {
        if (::sem_wait(sem_.get()) < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    bool try_acquire(long wait_ms = 0)
    {
        if (wait_ms == 0) {
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
                                (system_clock::now() + milliseconds(wait_ms)).time_since_epoch())
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

    void park()
    {
        sem_.acquire();
    }

    void unpark()
    {
        sem_.release();
    }

  private:
    semaphore sem_;
};

class wait_group
{
  public:
    explicit wait_group(int nmemb = 0)
        : sem_(0)
        , nmemb_(nmemb)
    {
    }

    void add(int delta = 1)
    {
        nmemb_ += delta;
    }

    void done()
    {
        sem_.release();
    }

    bool wait(int wait_ms = -1)
    {
        if (wait_ms == -1) {
            while (nmemb_ > 0) {
                sem_.acquire();
                --nmemb_;
            }

        } else {
            using namespace std::chrono;
            auto remaining_ms = wait_ms;
            while (nmemb_ > 0) {
                auto t = steady_clock::now();
                if (!sem_.try_acquire(remaining_ms)) {
                    return false;
                }
                auto elapsed_ms = (long)std::round(
                    duration_cast<duration<float, std::milli>>(steady_clock::now() - t).count());
                if (elapsed_ms >= remaining_ms) {
                    return false;
                }
                remaining_ms -= elapsed_ms;
                --nmemb_;
            }
        }

        return true;
    }

  private:
    semaphore sem_;
    std::atomic<int> nmemb_{0};
};

}  // namespace tbd

#endif
