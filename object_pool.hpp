#ifndef OBJECT_POOL_HPP_
#define OBJECT_POOL_HPP_

#include <cassert>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <vector>

namespace tbd {

using std::swap;

template <typename T> class object_pool;

template <typename T>
class pooled_object
{
    friend class object_pool<T>;
    using pool = object_pool<T>;
    using deleter_t = std::function<void(T*)>;

  public:
    pooled_object(const pooled_object&) = delete;
    pooled_object& operator=(const pooled_object&) = delete;

    pooled_object(pooled_object&& rhs)
    {
        *this = std::move(rhs);
    }
    pooled_object& operator=(pooled_object&& rhs)
    {
        if (this != &rhs) {
            swap(obj_, rhs.obj_);
            pool_.swap(rhs.pool_);
            delete_object_.swap(rhs.delete_object_);
        }
        return *this;
    }

    ~pooled_object()
    {
        if (obj_) {
            if (auto p = pool_.lock()) {
                p->release(obj_);

            } else if (delete_object_) {
                delete_object_(obj_);

            } else {
                delete obj_;
            }

            obj_ = nullptr;
        }
    }

    explicit operator bool() const noexcept
    {
        return !!obj_;
    }
    T& operator*() const& noexcept
    {
        return *obj_;
    }
    T* operator->() const& noexcept
    {
        return obj_;
    }

  private:
    T* obj_ = nullptr;
    std::weak_ptr<pool> pool_;
    deleter_t delete_object_;

    pooled_object() = default;

    pooled_object(T* o, const std::shared_ptr<pool>& p, const deleter_t& d = {})
        : obj_(o), pool_(p), delete_object_(d)
    {
        //
    }
};

template <typename T>
class object_pool : public std::enable_shared_from_this<object_pool<T>>
{
    friend class pooled_object<T>;
    using object = pooled_object<T>;
    using pool = object_pool<T>;
    using builder_t = std::function<T*(void)>;
    using deleter_t = std::function<void(T*)>;

  public:
    struct option
    {
        uint32_t max_objects = 100;
        builder_t new_object;
        deleter_t delete_object = [](T* o) { delete o; };
    };

    // factory
    static std::shared_ptr<pool> create(builder_t&& b, deleter_t&& d = {})
    {
        return std::shared_ptr<pool>(
                new pool(std::forward<builder_t>(b), std::forward<deleter_t>(d)));
    }
    static std::shared_ptr<pool> create(const option& opt)
    {
        return std::shared_ptr<pool>(new pool(opt));
    }

    ~object_pool()
    {
        for (const auto& o : objs_) {
            opts_.delete_object(o);
        }
    }

    object acquire(long wait_ms = -1)
    {
        T* o = nullptr;

        {
            std::unique_lock<std::mutex> lk(mtx_);

            if (objs_.empty()) {
                if (nr_objs_ < opts_.max_objects) {
                    objs_.push_back(opts_.new_object());
                    ++nr_objs_;

                } else if (wait_ms == 0) {
                    return object();

                } else if (wait_ms < 0) {
                    cv_.wait(lk, [this] { return !objs_.empty(); });

                } else {
                    bool ok = cv_.wait_for(lk, std::chrono::milliseconds(wait_ms),
                                           [this] { return !objs_.empty(); });
                    if (!ok) {
                        return object();
                    }
                }
            }

            o = objs_.back();
            objs_.pop_back();
        }  // unlock

        assert(!!o);
        return object(o, this->shared_from_this(), opts_.delete_object);
    }

  private:
    option opts_;
    size_t nr_objs_ = 0;
    std::mutex mtx_;
    std::condition_variable cv_;
    std::vector<T*> objs_;

    explicit object_pool(builder_t&& b, deleter_t&& d)
    {
        opts_.new_object = std::forward<builder_t>(b);
        if (!opts_.new_object) {
            throw std::logic_error("object_pool: builder not callable");
        }

        if (!!d) {
            opts_.delete_object = std::forward<deleter_t>(d);
        }
    }

    explicit object_pool(const option& opt) : opts_(opt)
    {
        if (!opts_.new_object) {
            throw std::logic_error("object_pool: builder not callable");
        }
    }

    void release(T* o)
    {
        std::lock_guard<std::mutex> lk(mtx_);
        objs_.push_back(o);
        cv_.notify_one();
    }
};

}  // namespace tbd

#endif
