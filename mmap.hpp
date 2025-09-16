#ifndef MMAP_HPP_
#define MMAP_HPP_

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <system_error>
#include <utility>

namespace tbd {

class mmapper
{
  public:
    explicit mmapper(std::string_view filename)
    {
        if ((fd_ = ::open(filename.data(), O_RDONLY)) < 0) {
            throw std::system_error(errno, std::generic_category());
        }

        if (::fstat(fd_, &statbuf_) < 0) {
            ::close(fd_);
            throw std::system_error(errno, std::generic_category());
        }

        if ((area_ = ::mmap(nullptr, statbuf_.st_size, PROT_READ, MAP_PRIVATE, fd_, 0)) ==
            MAP_FAILED) {
            ::close(fd_);
            throw std::system_error(errno, std::generic_category());
        }

        ::posix_madvise(area_, statbuf_.st_size, POSIX_MADV_WILLNEED);
    }

    mmapper(const mmapper&) = delete;
    mmapper& operator=(const mmapper&) = delete;
    mmapper(mmapper&& rhs) noexcept
        : fd_(std::exchange(rhs.fd_, -1))
        , statbuf_(std::exchange(rhs.statbuf_, {}))
        , area_(std::exchange(rhs.area_, nullptr))
    {
    }
    mmapper& operator=(mmapper&& rhs) noexcept
    {
        if (this != &rhs) {
            cleanup();
            fd_ = std::exchange(rhs.fd_, -1);
            statbuf_ = std::exchange(rhs.statbuf_, {});
            area_ = std::exchange(rhs.area_, nullptr);
        }
        return *this;
    }

    ~mmapper()
    {
        cleanup();
    }

    const void* data() const noexcept
    {
        return area_;
    }

    size_t size() const noexcept
    {
        return statbuf_.st_size;
    }

  private:
    int fd_ = -1;
    struct stat statbuf_ = {};
    void* area_ = nullptr;

    void cleanup() noexcept
    {
        if (area_) {
            ::munmap(area_, statbuf_.st_size);
            area_ = nullptr;
        }
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }
};

}  // namespace tbd

#endif
