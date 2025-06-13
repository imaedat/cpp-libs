#ifndef PIPE_HPP_
#define PIPE_HPP_

#include <unistd.h>

#include <cstring>
#include <string>
#include <system_error>

namespace tbd {

class pipe
{
    static void close_(int& fd)
    {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }

  public:
    pipe()
    {
        if (::pipe(fds_) < 0) {
            throw std::system_error(errno, std::generic_category());
        }
    }

    pipe(const pipe&) = delete;
    pipe& operator=(const pipe&) = delete;
    pipe(pipe&& rhs) noexcept
        : fds_{rhs.fds_[0], rhs.fds_[1]}
    {
        rhs.fds_[0] = rhs.fds_[1] = -1;
    }
    pipe& operator=(pipe&& rhs) noexcept
    {
        if (this != &rhs) {
            for (size_t i = 0; i < 2; ++i) {
                fds_[i] = rhs.fds_[i];
                rhs.fds_[i] = -1;
            }
        }
        return *this;
    }

    ~pipe()
    {
        close_(fds_[0]);
        close_(fds_[1]);
    }

    class writer
    {
      public:
        writer(const writer&) = delete;
        writer& operator=(const writer&) = delete;
        writer(writer&& rhs) noexcept
            : wfd_(rhs.wfd_)
        {
            rhs.wfd_ = -1;
        }
        writer& operator=(writer&& rhs) noexcept
        {
            if (this != &rhs) {
                close_(wfd_);
                wfd_ = rhs.wfd_;
                rhs.wfd_ = -1;
            }
            return *this;
        }

        ~writer()
        {
            close_(wfd_);
        }

        int handle() const noexcept
        {
            return wfd_;
        }

        size_t write(const void* buf, size_t size)
        {
            auto nwritten = ::write(wfd_, buf, size);
            if (nwritten < 0) {
                throw std::system_error(errno, std::generic_category());
            }
            return nwritten;
        }

        size_t write(std::string_view data)
        {
            return write(data.data(), data.size());
        }

      private:
        friend class pipe;
        int wfd_ = -1;

        explicit writer(int fds[])
            : wfd_(fds[1])
        {
            if (wfd_ < 0) {
                throw std::logic_error("writer has already been taken");
            }
            close_(fds[0]);
            fds[1] = -1;
        }
    };

    class reader
    {
      public:
        reader(const reader&) = delete;
        reader& operator=(const reader&) = delete;
        reader(reader&& rhs) noexcept
            : rfd_(rhs.rfd_)
        {
            rhs.rfd_ = -1;
        }
        reader& operator=(reader&& rhs) noexcept
        {
            if (this != &rhs) {
                close_(rfd_);
                rfd_ = rhs.rfd_;
                rhs.rfd_ = -1;
            }
            return *this;
        }

        ~reader()
        {
            close_(rfd_);
        }

        int handle() const noexcept
        {
            return rfd_;
        }

        size_t read(void* buf, size_t size)
        {
            auto nread = ::read(rfd_, buf, size);
            if (nread < 0) {
                throw std::system_error(errno, std::generic_category());
            }
            return nread;
        }

        std::string read()
        {
            constexpr size_t BUFSZ = 1024;
            char buf[BUFSZ] = {0};
            std::string result;
            while (auto nread = read(buf, BUFSZ)) {
                result += buf;
                if (nread < BUFSZ) {
                    break;
                }
                ::memset(buf, 0, BUFSZ);
            }
            return result;
        }

      private:
        friend class pipe;
        int rfd_ = -1;

        explicit reader(int fds[])
            : rfd_(fds[0])
        {
            if (rfd_ < 0) {
                throw std::logic_error("reader has already been taken");
            }
            fds[0] = -1;
            close_(fds[1]);
        }
    };

    writer get_writer()
    {
        return writer(fds_);
    }

    reader get_reader()
    {
        return reader(fds_);
    }

  private:
    int fds_[2] = {-1, -1};
};

}  // namespace tbd

#endif
