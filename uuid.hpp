#ifndef UUID_HPP_
#define UUID_HPP_

#include <endian.h>
#include <stdexcept>
#include <sys/random.h>

#include <array>
#include <chrono>
#include <cstring>
#include <functional>
#include <ostream>
#include <string>
#include <tuple>

namespace tbd {

class uuid
{
    inline static constexpr unsigned NS_PER_MS = 1000 * 1000;
    static constexpr std::tuple<bool, bool, uint8_t> validate(size_t i, char c)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            return {c == '-', true, 0};
        }
        if ('0' <= c && c <= '9') {
            return {true, false, c - '0'};
        }
        if ('a' <= c && c <= 'f') {
            return {true, false, c - 'a' + 10};
        }
        if ('A' <= c && c <= 'F') {
            return {true, false, c - 'A' + 10};
        }
        return {false, false, 0};
    }

    std::array<uint8_t, 16> bytes_{};

  public:
    uuid() noexcept = default;

    static uuid v4() noexcept
    {
        uuid newid;
        [[maybe_unused]] auto _ = ::getrandom(newid.bytes_.data(), newid.bytes_.size(), 0);
        newid.bytes_[6] = (newid.bytes_[6] & 0x0fU) | 0x40U;
        newid.bytes_[8] = (newid.bytes_[8] & 0x3fU) | 0x80U;
        return newid;
    }

    static uuid v7() noexcept
    {
        using namespace std::chrono;

        uuid newid;
        uint64_t now = duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count();
        uint64_t ts_rand = ((now / NS_PER_MS) << 16) | (7U << 12);
        uint16_t ns = (((now % NS_PER_MS) << 12) + (NS_PER_MS / 2)) / NS_PER_MS;
        ts_rand = ::htobe64(ts_rand | std::min(ns, (uint16_t)0x0fffU));
        std::memcpy(newid.bytes_.data(), &ts_rand, 8);
        [[maybe_unused]] auto _ = ::getrandom(newid.bytes_.data() + 8, 8, 0);
        newid.bytes_[8] = (newid.bytes_[8] & 0x3fU) | 0x80U;
        return newid;
    }

    static uuid from_bytes(const void* buf) noexcept
    {
        uuid newid;
        std::memcpy(newid.bytes_.data(), buf, newid.bytes_.size());
        return newid;
    }

    static uuid from_string(std::string_view s)
    {
        if (s.size() < 36 || (s.size() > 36 && s[36] != '\0')) {
            throw std::invalid_argument("not uuid format");
        }

        uuid newid;
        uint8_t* b = newid.bytes_.data();
        const char* p = s.data();
        for (size_t i = 0; i < 36;) {
            auto [hi_ok, hyphen, hi] = validate(i++, *p++);
            if (!hi_ok) {
                throw std::invalid_argument("not uuid format");
            }
            if (hyphen) {
                continue;
            }
            auto [lo_ok, _, lo] = validate(i++, *p++);
            if (!lo_ok) {
                throw std::invalid_argument("not uuid format");
            }
            *b++ = (hi << 4) | lo;
        }

        return newid;
    }

    std::string to_string() const
    {
        static constexpr const char hex[] = "0123456789abcdef";

        std::string s(36, '\0');
        auto* p = s.data();
        for (size_t i = 0; i < size(); ++i) {
            *p++ = hex[bytes_[i] >> 4];
            *p++ = hex[bytes_[i] & 0x0fU];
            if (i == 3 || i == 5 || i == 7 || i == 9) {
                *p++ = '-';
            }
        }
        return s;
    }

    const uint8_t* data() const noexcept
    {
        return bytes_.data();
    }

    constexpr size_t size() const noexcept
    {
        return bytes_.size();
    }

    void write_to(void* buf) const noexcept
    {
        std::memcpy(buf, data(), size());
    }

    std::chrono::system_clock::time_point time_point() const noexcept
    {
        uint64_t ns;
        std::memcpy(&ns, data(), 8);
        ns = ::be64toh(ns);
        ns = ((ns >> 16) * NS_PER_MS) + ((((ns & 0x0fffU) * NS_PER_MS) + 2048) >> 12);
        return std::chrono::system_clock::time_point(std::chrono::nanoseconds(ns));
    }

    int version() const noexcept
    {
        return data()[6] >> 4;
    }

    bool nil() const noexcept
    {
        return std::all_of(bytes_.begin(), bytes_.end(), [](uint8_t b) { return b == 0; });
    }

    bool operator==(const uuid& rhs) const noexcept
    {
        return bytes_ == rhs.bytes_;
    }

    bool operator!=(const uuid& rhs) const noexcept
    {
        return bytes_ != rhs.bytes_;
    }

    bool operator<(const uuid& rhs) const noexcept
    {
        return bytes_ < rhs.bytes_;
    }

    bool operator<=(const uuid& rhs) const noexcept
    {
        return bytes_ <= rhs.bytes_;
    }

    bool operator>(const uuid& rhs) const noexcept
    {
        return bytes_ > rhs.bytes_;
    }

    bool operator>=(const uuid& rhs) const noexcept
    {
        return bytes_ >= rhs.bytes_;
    }
};

}  // namespace tbd

inline std::ostream& operator<<(std::ostream& os, const tbd::uuid& u)
{
    return (os << u.to_string());
}

template <>
struct std::hash<tbd::uuid>
{
    size_t operator()(const tbd::uuid& u) const noexcept
    {
        return std::hash<std::string_view>{}(std::string_view((const char*)u.data(), u.size()));
    }
};

#endif
