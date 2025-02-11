#ifndef PARKER_HPP_
#define PARKER_HPP_

#include <semaphore.h>

#include <memory>

namespace tbd {

class parker
{
  public:
    parker() noexcept
        : sem_(std::make_unique<sem_t>())
    {
        sem_init(sem_.get(), 0, 0);
    }

    ~parker()
    {
        if (sem_) {
            sem_destroy(sem_.get());
        }
    }

    parker(const parker&) = delete;
    parker& operator=(const parker&) = delete;

    parker(parker&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    parker& operator=(parker&& rhs) noexcept
    {
        if (this != &rhs) {
            sem_.swap(rhs.sem_);
        }
        return *this;
    }

    void park()
    {
        sem_wait(sem_.get());
    }

    void unpark()
    {
        sem_post(sem_.get());
    }

  private:
    std::unique_ptr<sem_t> sem_;
};

}  // namespace tbd

#endif
