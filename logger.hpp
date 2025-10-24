#ifndef LOGGER_HPP_
#define LOGGER_HPP_

#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>

namespace tbd {

/*
 * "YYYY-mm-dd HH:MM:SS.NNNNNN proc[pid:tid] [level] msg..."
 */
class logger
{
  public:
    static constexpr size_t MAX_MSGS = 8192;

    enum class level : uint8_t
    {
        fatal = 1,
        error,
        warn,
        info,
        debug,
        trace,
    };

    logger(std::string_view proc, std::string_view filename, std::string_view dir = ".",
           size_t max_msg = MAX_MSGS)
        : pid_(getpid())
        , proc_(proc)
        , max_msgs_(max_msg)
    {
        std::filesystem::create_directories(dir);
        std::string path(dir);
        path.append("/").append(filename);
        fp_ = ::fopen(path.data(), "a");
        if (!fp_) {
            throw std::system_error(errno, std::generic_category(), "logger");
        }

        writer_ = std::thread([this] { writer(); });
    }

    ~logger()
    {
        stop();
        if (writer_.joinable()) {
            writer_.join();
        }
    }

    void set_level(level lv)
    {
        level_ = lv;
    }

    void set_level(int lv)
    {
        set_level((level)lv);
    }

    template <typename... Args>
    void fatal(Args&&... args)
    {
        log(level::fatal, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void error(Args&&... args)
    {
        log(level::error, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void warn(Args&&... args)
    {
        log(level::warn, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void info(Args&&... args)
    {
        log(level::info, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void debug(Args&&... args)
    {
        log(level::debug, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void trace(Args&&... args)
    {
        log(level::trace, std::forward<Args>(args)...);
    }

    void flush()
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        msgq_.emplace_back(request(req_type::flush));
        cv_.notify_one();
    }

    void stop()
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        msgq_.emplace_back(request(req_type::stop));
        cv_.notify_one();
    }

    void force_stop()
    {
        std::lock_guard<decltype(mtx_)> lk(mtx_);
        msgq_.emplace_front(request(req_type::stop));  // front
        cv_.notify_one();
    }

  private:
    enum class req_type : uint8_t
    {
        log = 1,
        flush,
        rotate,  // TODO
        stop,
    };
    struct request
    {
        req_type type;
        struct timespec timestamp;
        pid_t tid;
        logger::level level;
        std::string message;

        request() noexcept = default;
        request(req_type c) noexcept
            : type(c)
        {
        }
        request(const request&) = delete;
        request(request&&) noexcept = default;
    };

    pid_t pid_;
    std::string proc_;
    std::atomic<enum level> level_{level::info};
    size_t max_msgs_;
    FILE* fp_ = nullptr;
    std::thread writer_;
    std::deque<request> msgq_;
    std::mutex mtx_;
    std::condition_variable cv_;

    template <typename T>
    auto pass(T&& value)
    {
        if constexpr (std::is_same<std::remove_cv_t<std::remove_reference_t<T>>,
                                   std::string>::value) {
            return std::forward<T>(value).c_str();
        } else {
            return std::forward<T>(value);
        }
    }

    template <typename... Args>
    std::string format(Args&&... args)
    {
        auto size = ::snprintf(nullptr, 0, args...);
        std::string buf(size + 1, 0);
        ::snprintf(buf.data(), size + 1, args...);
        return buf;
    }

    template <typename... Args>
    void log(level lv, Args&&... args)
    {
        if (lv <= level_) {
            request req(req_type::log);
            ::clock_gettime(CLOCK_REALTIME, &req.timestamp);
            req.tid = syscall(SYS_gettid);
            req.level = lv;
            req.message = format(pass(args)...);

            // TODO max msg
            std::lock_guard<decltype(mtx_)> lk(mtx_);
            msgq_.emplace_back(std::move(req));
            cv_.notify_one();
        }
    }

    void writer()
    {
        std::unique_lock<decltype(mtx_)> lk(mtx_);
        while (true) {
            cv_.wait(lk, [this] { return !msgq_.empty(); });

            auto req = std::move(msgq_.front());
            msgq_.pop_front();
            lk.unlock();

            switch (req.type) {
            case req_type::log:
                log_msg(req);
                break;

            case req_type::flush:
                ::fflush(fp_);
                break;

            case req_type::stop:
                goto stop;

            default:
                break;
            }

            lk.lock();
        }

    stop:
        ::fclose(fp_);
    }

    void log_msg(request& req)
    {
        static constexpr const char* const level_s[] = {"dummy", "fatal", "error", "warn",
                                                        "info",  "debug", "trace"};
        struct tm tm = {};
        ::localtime_r(&req.timestamp.tv_sec, &tm);
        ::fprintf(fp_, "%04d-%02d-%02d %02d:%02d:%02d.%06ld %s[%d:%d] [%s] %s\n", tm.tm_year + 1900,
                  tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                  req.timestamp.tv_nsec / 1000, proc_.c_str(), pid_, req.tid,
                  level_s[(uint8_t)req.level], req.message.c_str());
    }
};

}  // namespace tbd

#endif
