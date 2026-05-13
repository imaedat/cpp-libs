#ifndef JSON_HPP_
#define JSON_HPP_

#include <algorithm>
#include <cassert>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace tbd {

class json
{
  public:
    inline static constexpr size_t VALUE_BUFFER_SIZE = 64;
    using object_type = std::unordered_map<std::string, json>;
    using array_type = std::vector<json>;

  private:
    [[noreturn]] static void throw_invalid(const std::string& f, std::string_view m)
    {
        throw std::invalid_argument(f + ": " + m.data());
    }

    using value_type = std::variant<std::monostate, bool, int64_t, double, std::string, json>;
    template <typename T>
    inline static constexpr bool string_like =
        std::is_convertible_v<std::decay_t<T>, std::string_view>;
    inline static constexpr size_t num_offset =
        (sizeof(std::string) + alignof(std::max_align_t) - 1) & ~(alignof(std::max_align_t) - 1);
    static_assert(num_offset + std::max(sizeof(int64_t), sizeof(double)) <= VALUE_BUFFER_SIZE);
    union number
    {
        int64_t i;
        double d;
    };

    alignas(alignof(std::max_align_t)) uint8_t buffer_[VALUE_BUFFER_SIZE] = {0};
    mutable size_t textsize_ = 0;
    enum class value_t : uint8_t
    {
        null,
        boolean,
        integral,
        integral_uncached,
        floating,
        floating_uncached,
        string,
        unescaped_string,
        object,
        array,
    } type_{value_t::null};

    void alloc(value_t type)
    {
        switch (type) {
        case value_t::null:
            break;

        case value_t::boolean:
            new (buffer_) bool();
            break;

        case value_t::integral:
        case value_t::integral_uncached:
        case value_t::floating:
        case value_t::floating_uncached:
        case value_t::string:
        case value_t::unescaped_string:
            new (buffer_) std::string();
            break;

        case value_t::object:
            new (buffer_) object_type();
            break;

        case value_t::array:
            new (buffer_) array_type();
            break;

        default:
            __builtin_unreachable();
        }

        type_ = type;
    }

    template <typename V>
    void alloc_with(value_t type, V&& v, union number n = {})
    {
        if constexpr (std::is_same_v<std::decay_t<V>, bool>) {
            assert(type == value_t::boolean);
            new (buffer_) bool(v);
            type_ = type;

        } else if constexpr (string_like<V>) {
            assert(type == value_t::integral || type == value_t::integral_uncached ||
                   type == value_t::floating || type == value_t::floating_uncached ||
                   type == value_t::string || type == value_t::unescaped_string);
            if (type == value_t::unescaped_string) {
                new (buffer_) std::string(escape_(std::forward<V>(v)));
                type_ = value_t::string;

            } else {
                new (buffer_) std::string(std::forward<V>(v));
                type_ = type;
                if (type_ == value_t::integral) {
                    cache_number<int64_t>(this, n.i);
                } else if (type_ == value_t::floating) {
                    cache_number<double>(this, n.d);
                }
            }

        } else if constexpr (std::is_same_v<std::decay_t<V>, object_type>) {
            assert(type == value_t::object);
            new (buffer_) object_type(std::forward<V>(v));
            type_ = type;

        } else if constexpr (std::is_same_v<std::decay_t<V>, array_type>) {
            assert(type == value_t::array);
            new (buffer_) array_type(std::forward<V>(v));
            type_ = type;

        } else {
            static_assert([] { return false; }(), "invalid argument");
        }
    }

    explicit json(value_t type)
    {
        alloc(type);
    }

    template <typename V>
    json(value_t type, V&& v, union number n = {})
    {
        alloc_with(type, std::forward<V>(v), n);
    }

  public:
    json()
        : json(value_t::null)
    {
    }
    template <typename V,
              std::enable_if_t<(std::is_same_v<std::decay_t<V>, bool> ||
                                std::is_arithmetic_v<std::decay_t<V>> || string_like<V> ||
                                std::is_same_v<std::decay_t<V>, json>),
                               bool> = true>
    explicit json(V&& v)
    {
        union number n;
        if constexpr (std::is_same_v<std::decay_t<V>, bool>) {
            alloc_with(value_t::boolean, v);
        } else if constexpr (std::is_integral_v<std::decay_t<V>>) {
            n.i = v;
            alloc_with(value_t::integral, std::to_string(v), n);
        } else if constexpr (std::is_floating_point_v<std::decay_t<V>>) {
            n.d = v;
            alloc_with(value_t::floating, to_string(v), n);
        } else if constexpr (string_like<V>) {
            alloc_with(value_t::unescaped_string, std::forward<V>(v));
        } else if constexpr (std::is_same_v<std::decay_t<V>, json>) {
            operator=(std::forward<V>(v));
        } else {
            static_assert([] { return false; }(), "invalid argument");
        }
    }
    json(const std::initializer_list<std::pair<std::string, value_type>>& list)
    {
        struct keyvalue_visitor
        {
            object_type* obj;
            const std::string& k;
            union number n;
            // clang-format off
            void operator()(std::monostate) { obj->emplace(k, json(value_t::null)); }
            void operator()(bool v) { obj->emplace(k, json(value_t::boolean, v)); }
            void operator()(int64_t v) { n.i = v; obj->emplace(k, json(value_t::integral, std::to_string(v), n)); }
            void operator()(double v) { n.d = v; obj->emplace(k, json(value_t::floating, to_string(v), n)); }
            void operator()(const std::string& v) { obj->emplace(k, json(value_t::unescaped_string, v)); }
            void operator()(const json& v) { obj->emplace(k, v); }
            // clang-format on
        };

        alloc(value_t::object);
        auto* obj = to_obj_();
        for (auto&& [k, v] : list) {
            keyvalue_visitor kvv{obj, unescape_(k), {}};
            std::visit(kvv, v);
        }
    }
    json(const std::initializer_list<value_type>& list)
    {
        struct value_visitor
        {
            array_type* arr;
            union number n;
            // clang-format off
            void operator()(std::monostate) { arr->emplace_back(json(value_t::null)); }
            void operator()(bool v) { arr->emplace_back(json(value_t::boolean, v)); }
            void operator()(int64_t v) { n.i = v; arr->emplace_back(json(value_t::integral, std::to_string(v), n)); }
            void operator()(double v) { n.d = v; arr->emplace_back(json(value_t::floating, to_string(v), n)); }
            void operator()(const std::string& v) { arr->emplace_back(json(value_t::unescaped_string, v)); }
            void operator()(const json& v) { arr->emplace_back(v); }
            // clang-format on
        };

        alloc(value_t::array);
        auto* arr = to_arr_();
        for (auto&& v : list) {
            value_visitor vv{arr, {}};
            std::visit(vv, v);
        }
    }

  private:
    template <typename T>
    void forward_(T&& rhs)
    {
        switch (rhs.type_) {
        case value_t::null:
            break;

        case value_t::boolean:
            new (buffer_) bool(*rhs.to_bool_());
            break;

        case value_t::integral:
        case value_t::integral_uncached:
        case value_t::floating:
        case value_t::floating_uncached:
        case value_t::string:
            if constexpr (std::is_const_v<std::remove_reference_t<T>>) {
                new (buffer_) std::string(std::forward<const std::string&>(*rhs.to_str_()));
            } else {
                new (buffer_) std::string(std::forward<std::string&&>(*rhs.to_str_()));
            }
            copy_number(rhs);
            break;

        case value_t::object:
            if constexpr (std::is_const_v<std::remove_reference_t<T>>) {
                new (buffer_) object_type(std::forward<const object_type&>(*rhs.to_obj_()));
            } else {
                new (buffer_) object_type(std::forward<object_type&&>(*rhs.to_obj_()));
            }
            break;

        case value_t::array:
            if constexpr (std::is_const_v<std::remove_reference_t<T>>) {
                new (buffer_) array_type(std::forward<const array_type&>(*rhs.to_arr_()));
            } else {
                new (buffer_) array_type(std::forward<array_type&&>(*rhs.to_arr_()));
            }
            break;

        default:
            __builtin_unreachable();
        }

        type_ = rhs.type_;
        textsize_ = rhs.textsize_;
    }
    void move_(json&& rhs) noexcept
    {
        assert(is_null());
        forward_(std::move(rhs));
        rhs.reset();
    }

  public:
    json(const json& rhs)
    {
        forward_(rhs);
    }
    json(json&& rhs) noexcept
    {
        move_(std::move(rhs));
    }
    json& operator=(const json& rhs)
    {
        if (this != &rhs) {
            json tmp(rhs);
            swap(*this, tmp);
        }
        return *this;
    }
    json& operator=(json&& rhs) noexcept
    {
        if (this != &rhs) {
            swap(*this, rhs);
        }
        return *this;
    }
    ~json()
    {
        reset();
    }

    friend void swap(json& lhs, json& rhs) noexcept
    {
        if (&lhs != &rhs) {
            json tmp(std::move(lhs));
            lhs.move_(std::move(rhs));
            rhs.move_(std::move(tmp));
        }
    }

    static json parse(const std::string& s)
    {
        parser p(s);
        auto j = p.parse();
        j.textsize_ = p.offset();
        return j;
    }

    static json load(std::string_view file)
    {
        using namespace std::string_literals;
        std::ifstream ifs(file.data());
        if (!ifs) {
            throw_invalid(__func__, "cannot open file: "s + file.data());
        }
        using iterator = std::istreambuf_iterator<char>;
        return parse(std::string(iterator(ifs), iterator()));
    }

    std::string to_string() const
    {
        std::string ss;
        ss.reserve(std::max(textsize_, (size_t)512));
        stringify_(ss);
        textsize_ = ss.size();
        return ss;
    }

    /************************************************************************
     * const attributes
     */
    // clang-format off
    bool is_null() const { return type_ == value_t::null; }
    bool is_bool() const { return type_ == value_t::boolean; }
    bool is_integer() const { return type_ == value_t::integral ||
                                     type_ == value_t::integral_uncached; }
    bool is_floating() const { return type_ == value_t::floating ||
                                      type_ == value_t::floating_uncached; }
    bool is_number() const { return is_integer() || is_floating(); }
    bool is_string() const { return type_ == value_t::string; }
    bool is_primitive() const { return is_null() || is_bool() || is_number() || is_string(); }
    bool is_object() const { return type_ == value_t::object; }
    bool is_array() const { return type_ == value_t::array; }
    bool is_structured() const { return is_object() || is_array(); }
    // clang-format on

    bool empty() const
    {
        switch (type_) {
        case value_t::string:
            return to_str_()->empty();

        case value_t::object:
            return to_obj_()->empty();

        case value_t::array:
            return to_arr_()->empty();

        default:
            throw_invalid(__func__, "not container");
        }
    }

    size_t size() const
    {
        switch (type_) {
        case value_t::string:
            return get<std::string>().size();

        case value_t::object:
            return to_obj_()->size();

        case value_t::array:
            return to_arr_()->size();

        default:
            throw_invalid(__func__, "not container");
        }
    }

    /************************************************************************
     * common operator
     */
    template <typename V, std::enable_if_t<!std::is_same_v<std::decay_t<V>, json>, bool> = true>
    json& operator=(V&& v)
    {
        json rhs(std::forward<V>(v));
        swap(*this, rhs);
        return *this;
    }

    bool operator==(const json& rhs) const
    {
        switch (type_) {
        case value_t::null:
            return rhs.is_null();

        case value_t::boolean:
            return rhs.is_bool() && *to_bool_() == *rhs.to_bool_();

        case value_t::integral:
        case value_t::integral_uncached:
            return (rhs.is_integer() && get<int64_t>() == rhs.get<int64_t>()) ||
                   (rhs.is_floating() && get<double>() == rhs.get<double>());

        case value_t::floating:
        case value_t::floating_uncached:
            return rhs.is_number() && get<double>() == rhs.get<double>();

        case value_t::string:
            return rhs.is_string() && get<std::string>() == rhs.get<std::string>();

        case value_t::object:
            return rhs.is_object() && *to_obj_() == *rhs.to_obj_();

        case value_t::array:
            return rhs.is_array() && *to_arr_() == *rhs.to_arr_();

        default:
            __builtin_unreachable();
        }
    }

    bool operator!=(const json& rhs) const
    {
        return !(*this == rhs);
    }

    template <typename T>
    T get() const
    {
        if constexpr (std::is_same_v<T, bool>) {
            if (auto* b = to_bool_()) {
                return *b;
            }

        } else if constexpr (std::is_arithmetic_v<T>) {
            if (type_ == value_t::integral_uncached) {
                cache_number<int64_t>(const_cast<json*>(this), to_number<int64_t>());
            } else if (type_ == value_t::floating_uncached) {
                cache_number<double>(const_cast<json*>(this), to_number<double>());
            }

            if (auto* num = to_int_()) {
                return *num;
            }
            if (auto* num = to_float_()) {
                return *num;
            }

        } else if constexpr (std::is_same_v<T, std::string>) {
            if (auto* str = to_str_(); str && is_string()) {
                return unescape_(*str);
            }

        } else {
            static_assert([] { return false; }(), "invalid type");
        }

        throw_invalid(__func__, "not primitive");
    }

    template <typename T, std::enable_if_t<std::is_arithmetic_v<T>, bool> = true>
    T get_or(T v)
    {
        if (is_null()) {
            operator=(v);
        }
        return get<T>();
    }

    template <typename T, std::enable_if_t<string_like<T>, bool> = true>
    std::string get_or(T&& v)
    {
        if (is_null()) {
            operator=(std::forward<T>(v));
        }
        return get<std::string>();
    }

    void clear()
    {
        switch (type_) {
        case value_t::string:
            to_str_()->clear();
            return;

        case value_t::object:
            to_obj_()->clear();
            return;

        case value_t::array:
            to_arr_()->clear();
            return;

        default:
            throw_invalid(__func__, "not container");
        }
    }

    void reset() noexcept
    {
        switch (type_) {
        case value_t::null:
        case value_t::boolean:
            break;

        case value_t::integral:
        case value_t::integral_uncached:
        case value_t::floating:
        case value_t::floating_uncached:
        case value_t::string:
        case value_t::unescaped_string:
            to_str_()->~basic_string();
            break;

        case value_t::object:
            to_obj_()->~unordered_map();
            break;

        case value_t::array:
            to_arr_()->~vector();
            break;

        default:
            break;
        }

        type_ = value_t::null;
        textsize_ = 0;
    }

    /************************************************************************
     * object operator
     */
    bool contains(const std::string& key) const
    {
        if (auto* obj = to_obj_()) {
            return obj->find(key) != obj->end();
        }
        throw_invalid(__func__, "not object");
    }

    const json& at(const std::string& key) const
    {
        if (auto* obj = to_obj_()) {
            return obj->at(key);
        }
        throw_invalid(__func__, "not object");
    }

    json& operator[](const std::string& key)
    {
        if (is_null()) {
            alloc(value_t::object);
        }
        if (auto* obj = to_obj_()) {
            auto it = obj->find(key);
            if (it == obj->end()) {
                std::tie(it, std::ignore) = obj->emplace(key, json{});
            }
            return it->second;
        }
        throw_invalid(__func__, "not object");
    }

#if 0
    template <typename K, typename V>
    void emplace(K&& k, V&& v)
    {
        if (auto* obj = to_obj_()) {
            obj->emplace(std::forward<K>(k), std::forward<V>(v));
            return;
        }
        throw_invalid(__func__, "not object");
    }
#endif

    void erase(const std::string& key)
    {
        if (auto* obj = to_obj_()) {
            obj->erase(key);
            return;
        }
        throw_invalid(__func__, "not object");
    }

    // --- object iterator ---
    struct object_iterator;
    struct object_view
    {
        object_type* obj;
        object_iterator begin();
        object_iterator end();
    };

    object_view items()
    {
        if (auto* obj = to_obj_()) {
            return object_view{obj};
        }
        throw_invalid(__func__, "not object");
    }

    /************************************************************************
     * array operator
     */
    const json& at(size_t i) const
    {
        if (auto* arr = to_arr_()) {
            return arr->at(i);
        }
        throw_invalid(__func__, "not array");
    }

    json& operator[](size_t i)
    {
        if (auto* arr = to_arr_()) {
            return (*arr)[i];
        }
        throw_invalid(__func__, "not array");
    }

    template <typename J, std::enable_if_t<std::is_same_v<std::decay_t<J>, json>, bool> = true>
    void push_back(J&& j)
    {
        if (is_null()) {
            alloc(value_t::array);
        }
        if (auto* arr = to_arr_()) {
            arr->push_back(std::forward<J>(j));
            return;
        }
        throw_invalid(__func__, "not array");
    }

    template <typename V, std::enable_if_t<!std::is_same_v<std::decay_t<V>, json>, bool> = true>
    void push_back(V&& v)
    {
        push_back(json(std::forward<V>(v)));
    }

    // --- array iterator ---
    struct array_iterator
    {
        array_type::iterator it;
        explicit array_iterator(array_type::iterator i)
            : it(i)
        {
        }
        json& operator*() const
        {
            return *it;
        }
        json* operator->() const
        {
            return &*it;
        }
        array_iterator& operator++()
        {
            ++it;
            return *this;
        }
        array_iterator operator++(int)
        {
            auto v = *this;
            ++(*this);
            return v;
        }
        bool operator==(const array_iterator& rhs) const
        {
            return it == rhs.it;
        }
        bool operator!=(const array_iterator& rhs) const
        {
            return !(*this == rhs);
        }
    };

    array_iterator begin()
    {
        if (auto* arr = to_arr_()) {
            return array_iterator(arr->begin());
        }
        throw_invalid(__func__, "not array");
    }

    array_iterator end()
    {
        if (auto* arr = to_arr_()) {
            return array_iterator(arr->end());
        }
        throw_invalid(__func__, "not array");
    }

  private:
    /************************************************************************
     * cast
     */
    template <typename T>
    T* cast_(bool ok, bool num = false)
    {
        return ok ? std::launder(reinterpret_cast<T*>(num ? numbuffer_() : buffer_)) : nullptr;
    }
    template <typename T>
    const T* cast_(bool ok, bool num = false) const
    {
        return ok ? std::launder(reinterpret_cast<const T*>(num ? numbuffer_() : buffer_))
                  : nullptr;
    }

    // clang-format off
          void* numbuffer_()       { return buffer_ + num_offset; }
    const void* numbuffer_() const { return buffer_ + num_offset; }

    bool holds_as_string() const { return is_integer() || is_floating() || is_string(); }

          object_type* to_obj_()         { return cast_<object_type>(is_object()); }
    const object_type* to_obj_() const   { return cast_<object_type>(is_object()); }
          array_type*  to_arr_()         { return cast_<array_type>(is_array()); }
    const array_type*  to_arr_() const   { return cast_<array_type>(is_array()); }
          std::string* to_str_()         { return cast_<std::string>(holds_as_string()); }
    const std::string* to_str_() const   { return cast_<std::string>(holds_as_string()); }
          int64_t*     to_int_()         { return cast_<int64_t>(is_integer(), true); }
    const int64_t*     to_int_() const   { return cast_<int64_t>(is_integer(), true); }
          double*      to_float_()       { return cast_<double>(is_floating(), true); }
    const double*      to_float_() const { return cast_<double>(is_floating(), true); }
          bool*        to_bool_()        { return cast_<bool>(is_bool()); }
    const bool*        to_bool_() const  { return cast_<bool>(is_bool()); }
    // clang-format on

    /************************************************************************
     * numbers
     */
    template <typename J, std::enable_if_t<std::is_same_v<std::decay_t<J>, json>, bool> = true>
    void copy_number(J&& j)
    {
        if (j.type_ == value_t::integral) {
            *(int64_t*)numbuffer_() = *j.to_int_();
        } else if (j.type_ == value_t::floating) {
            *(double*)numbuffer_() = *j.to_float_();
        }
    }

    template <typename T>
    static void cache_number(json* j, T v)
    {
        if constexpr (std::is_integral_v<T>) {
            *j->to_int_() = (int64_t)v;
            j->type_ = value_t::integral;
        } else if constexpr (std::is_floating_point_v<T>) {
            *j->to_float_() = (double)v;
            j->type_ = value_t::floating;
        } else {
            static_assert([] { return false; }(), "type error");
        }
    }

    template <typename T>
    T to_number() const
    {
        auto* s = to_str_();
        T v{};
        auto [_, ec] = std::from_chars(s->data(), s->data() + s->size(), v);
        if (ec != std::errc{}) {
            throw_invalid(__func__, "invalid numeric: " + *s);
        }
        return v;
    }

    static std::string to_string(double v)
    {
        char buf[64] = {0};
        auto [_, ec] = std::to_chars(buf, buf + sizeof(buf), v);
        if (ec != std::errc{}) {
            throw_invalid(__func__, "invalid numeric: " + std::to_string(v));
        }
        return buf;
    }

    /************************************************************************
     * stringify
     */
    void stringify_(std::string& ss) const
    {
        switch (type_) {
        case value_t::null:
            ss += "null";
            break;

        case value_t::boolean:
            ss += (*to_bool_() ? "true" : "false");
            break;

        case value_t::integral:
        case value_t::integral_uncached:
        case value_t::floating:
        case value_t::floating_uncached:
            ss += *to_str_();
            break;

        case value_t::string:
            ss.push_back('"');
            ss.append(*to_str_());
            ss.push_back('"');
            break;

        case value_t::object: {
            ss += "{";
            auto* obj = to_obj_();
            auto remains = obj->size();
            for (const auto& [k, v] : *obj) {
                ss.push_back('"');
                escape_(ss, k);
                ss.append("\":");
                v.stringify_(ss);
                if (--remains > 0) {
                    ss += ",";
                }
            }
            ss += "}";
            break;
        }

        case value_t::array: {
            ss += "[";
            auto* arr = to_arr_();
            auto remains = arr->size();
            for (const auto& v : *arr) {
                v.stringify_(ss);
                if (--remains > 0) {
                    ss += ",";
                }
            }
            ss += "]";
            break;
        }

        default:
            __builtin_unreachable();
        }
    }

    /************************************************************************
     * helper
     */
    static std::string escape_(std::string_view s)
    {
        std::string e;
        e.reserve(s.size());
        escape_(e, s);
        return e;
    }

    static void escape_(std::string& ss, std::string_view s)
    {
        static constexpr const char* const cntrl[] = {
            "\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006", "\\u0007",
            "\\b",     "\\t",     "\\n",     "\\u000B", "\\f",     "\\r",     "\\u000E", "\\u000F",
            "\\u0010", "\\u0011", "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017",
            "\\u0018", "\\u0019", "\\u001A", "\\u001B", "\\u001C", "\\u001D", "\\u001E", "\\u001F",
        };

        for (auto c : s) {
            if (c == '"') {
                ss.append("\\\"");
            } else if (c == '\\') {
                ss.append("\\\\");
            } else if ((unsigned char)c <= 0x1f) {
                ss.append(cntrl[(unsigned char)c]);
            } else {
                ss.push_back(c);
            }
        }
    }

    static std::string unescape_(std::string_view s)
    {
        std::string u;
        u.reserve(s.size());
        auto* p = s.data();
        while (true) {
            char c = *p++;
            if (c == '\0') {
                break;
            }
            if (c == '\\') {
                c = *p++;
                if (c == 'u') {
                    unescape_utf8(u, p);
                } else {
                    u.push_back(unescape_(c));
                }
            } else {
                u.push_back(c);
            }
        }
        return u;
    }

    static char unescape_(char c)
    {
        switch (c) {
        // clang-format off
        case 'b' : return '\b';
        case 't' : return '\t';
        case 'n' : return '\n';
        case 'f' : return '\f';
        case 'r' : return '\r';
        case '"' : return '"';
        case '/' : return '/';
        case '\\': return '\\';
        case 'u' : return 'u';
        case '\0': throw_invalid(__func__, "unexpected eof");
        default  : throw_invalid(__func__, "invalid escape sequence: (`" + std::string(1, c) + "')");
            // clang-format on
        }
    }

    /**
     * 0000h - 007Fh : 1B
     * 0080h - 07FFh : 2B
     * 0800h - D7FFh : 3B
     * D800h - DBFFh : high surrogate
     * DC00h - DFFFh : low surrogate
     * E000h - FFFFh : 3B
     */
    static void unescape_utf8(std::string& u, const char*& p)
    {
        const char* q = p;
        auto cp = decode_cp(p);

        if (cp <= 0x7f) {
            u.push_back((char)cp);
        } else if (cp <= 0x7ff) {
            u.push_back((char)(0xc0 | ((cp >> 6) & 0x1f)));
            u.push_back((char)(0x80 | (cp & 0x3f)));
        } else if (cp < 0xd800 || 0xdfff < cp) {
            u.push_back((char)(0xe0 | ((cp >> 12) & 0x0f)));
            u.push_back((char)(0x80 | ((cp >> 6) & 0x3f)));
            u.push_back((char)(0x80 | (cp & 0x3f)));
        } else {
            if (cp >= 0xdc00) {
                throw_invalid(__func__, "lone low surrogate: " + std::string(q, 4));
            }
            if (std::strncmp(p, "\\u", 2) != 0) {
                throw_invalid(__func__, "lone high surrogate: " + std::string(q, 4));
            }
            p += 2;
            q = p;
            auto lo = decode_cp(p);
            if (lo < 0xdc00 || 0xdfff < lo) {
                throw_invalid(__func__, "high surrogate followed by high: " + std::string(q, 4));
            }
            cp = (((cp - 0xd800) << 10) | (lo - 0xdc00)) + 0x10000;
            u.push_back((char)(0xf0 | ((cp >> 18) & 0x07)));
            u.push_back((char)(0x80 | ((cp >> 12) & 0x3f)));
            u.push_back((char)(0x80 | ((cp >> 6) & 0x3f)));
            u.push_back((char)(0x80 | (cp & 0x3f)));
        }
    }

    static uint32_t decode_cp(const char*& p)
    {
        unsigned cp = 0;
        for (int i = 0; i < 4; ++i) {
            char c = *p++;
            auto h = ('0' <= c && c <= '9')   ? c - '0'
                     : ('a' <= c && c <= 'f') ? c - 'a' + 10
                     : ('A' <= c && c <= 'F') ? c - 'A' + 10
                                              : -1;
            if (h < 0) {
                throw_invalid(__func__, "invalid code point (`" + std::string(1, c) + "')");
            }
            cp = (cp << 4) + h;
        }
        return cp;
    }

    /************************************************************************
     * parser
     */
    class parse_error : public std::invalid_argument
    {
      public:
        explicit parse_error(const std::string& what)
            : std::invalid_argument(what)
        {
        }
    };

    struct parser;
    struct stack
    {
        struct save
        {
            parser* p;
            std::string save_;
            ~save()
            {
                p->fn_ = std::move(save_);
            }
        };

        parser* p;
        save push(std::string f)
        {
            save s{p, std::move(p->fn_)};
            p->fn_ = std::move(f);
            return s;
        }
    };

    struct parser
    {
        const char *base_, *p_;
        std::string fn_;
        stack s_{this};

        parser(std::string_view s)
            : base_(s.data())
            , p_(base_)
        {
            skip_ws();
        }

        size_t offset() const
        {
            return p_ - base_;
        }

        json parse()
        {
            auto _ = s_.push(__func__);
            auto j = parse_value();
            if (*p_ != '\0') {
                throw_parser("unexpected char");
            }
            return j;
        }

        json parse_value()
        {
            auto _ = s_.push(__func__);
            switch (*p_) {
            case '{':
                return parse_object();

            case '[':
                return parse_array();

            case '"':
                return parse_string();

            // clang-format off
            case '0': case '1': case '2': case '3': case '4': case '5':
            case '6': case '7': case '8': case '9': case '-': case '.':
                // clang-format on
                return parse_number();

            // clang-format off
            case 't': case 'f': case 'n':
                // clang-format on
                return parse_literal();

            case '\0':
                return json{};

            default:
                throw_parser("unexpected char");
            }
        }

        json parse_object()
        {
            auto _ = s_.push(__func__);
            assert(*p_ == '{');
            skip_ws(1);
            json j(value_t::object);
            auto* obj = j.to_obj_();
            bool comma = false;
            while (*p_ != '}') {
                if (*p_ != '"') {
                    throw_parser("key not start with quote");
                }

                auto k = parse_string(true);
                if (*p_++ != ':') {
                    throw_parser("key-value not separated with colon", -1);
                }
                skip_ws();
                auto v = parse_value();
                obj->emplace(std::move(*k.to_str_()), std::move(v));

                skip_ws((comma = *p_ == ',') ? 1 : 0);
                if (!comma) {
                    break;
                }
            }
            if (comma) {
                throw_parser("next key-value expected");
            }
            if (*p_ != '}') {
                throw_parser("object not end with right-brace");
            }
            skip_ws(1);
            return j;
        }

        json parse_array()
        {
            auto _ = s_.push(__func__);
            assert(*p_ == '[');
            skip_ws(1);
            json j(value_t::array);
            auto* arr = j.to_arr_();
            bool comma = false;
            while (*p_ != ']') {
                auto v = parse_value();
                arr->emplace_back(std::move(v));
                skip_ws((comma = *p_ == ',') ? 1 : 0);
                if (!comma) {
                    break;
                }
            }
            if (comma) {
                throw_parser("next value expected");
            }
            if (*p_ != ']') {
                throw_parser("array not end with right-bracket");
            }
            skip_ws(1);
            return j;
        }

        json parse_string(bool is_key = false)
        {
            auto _ = s_.push(__func__);
            static constexpr const uint8_t pass[] = {
                // clang-format off
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
                // clang-format on
            };

            assert(*p_ == '"');
            auto base = ++p_;
            std::string s;
            while (true) {
                auto* q = p_;
                char c;
                while (pass[((unsigned char)(c = *p_++))])
                    ;
                if ((unsigned char)c <= 0x1f || (unsigned char)c == 0x7f) {
                    throw_parser("invalid character", -1);
                }
                if (c == '"') {
                    if (is_key && p_ > q + 1) {
                        s.append(q, p_ - q - 1);
                    }
                    break;
                }
                if (c == '\\') {
                    if (is_key && p_ > q + 1) {
                        s.append(q, p_ - q - 1);
                    }
                    c = *p_++;
                    if (c == 'u') {
                        if (is_key) {
                            unescape_utf8(s, p_);
                        } else {
                            (void)decode_cp(p_);
                        }
                        continue;
                    } else {
                        c = json::unescape_(c);
                    }
                    if (is_key) {
                        s.push_back(c);
                    }
                }
            }
            if (!is_key) {
                s.assign(base, p_ - base - 1);
            }
            skip_ws();
            return json(value_t::string, std::move(s));
        }

        json parse_number()
        {
            auto _ = s_.push(__func__);
            auto base = p_;
            if (*p_ == '-') {
                ++p_;
            }
            int len1 = -1, len2 = -1, len3 = -1;
            p_ += (len1 = std::strspn(p_, "0123456789"));  // int
            if (*p_ == '.') {
                p_ += (len2 = std::strspn(++p_, "0123456789"));  // frac
            }
            if (*p_ == 'e' || *p_ == 'E') {  // exp
                ++p_;
                if (*p_ == '+' || *p_ == '-') {
                    ++p_;
                }
                p_ += (len3 = std::strspn(p_, "0123456789"));
            }
            std::string s(base, p_ - base);
            if (len1 == 0 || (len1 >= 2 && (base[0] == '-' ? base[1] : base[0]) == '0') ||
                len2 == 0 || len3 == 0) {
                throw_parser("invalid numeric: " + s);
            }
            auto type =
                (len2 >= 0 || len3 > 0) ? value_t::floating_uncached : value_t::integral_uncached;
            skip_ws();
            return json(type, std::move(s));
        }

        json parse_literal()
        {
            auto _ = s_.push(__func__);
            if (std::strncmp(p_, "true", 4) == 0) {
                skip_ws(4);
                return json(value_t::boolean, true);
            }
            if (std::strncmp(p_, "false", 5) == 0) {
                skip_ws(5);
                return json(value_t::boolean, false);
            }
            if (std::strncmp(p_, "null", 4) == 0) {
                skip_ws(4);
                return json{};
            }
            throw_parser("unexpected literal");
        }

        void skip_ws(ptrdiff_t offset = 0) noexcept
        {
            p_ += offset + std::strspn(p_ + offset, " \t\r\n");
        }

        [[noreturn]] void throw_parser(std::string_view m, ptrdiff_t adjust = 0)
        {
            static constexpr const char hex[] = "0123456789ABCDEF";
            std::string what = fn_ + ": " + m.data();
            auto c = *(p_ + adjust);
            if (c >= 0) {
                if (c <= 0x1f) {
                    what.append(" <");
                    what.push_back(hex[c >> 4]);
                    what.push_back(hex[c & 0x0f]);
                    what.append("h>");
                } else {
                    what.append(" (`");
                    what.push_back((char)c);
                    what.append("')");
                }
            }
            what.append(", offset ");
            what.append(std::to_string(offset()));
            throw parse_error(what);
        }
    };
};

static_assert(sizeof(json::object_type) <= json::VALUE_BUFFER_SIZE);
static_assert(sizeof(json::array_type) <= json::VALUE_BUFFER_SIZE);

/****************************************************************************
 * object iterator
 */
struct json::object_iterator
{
    using value_proxy = std::pair<const std::string&, json&>;
    struct arrow_proxy
    {
        value_proxy v;
        value_proxy* operator->()
        {
            return &v;
        }
    };

    json::object_type::iterator it;
    explicit object_iterator(json::object_type::iterator i)
        : it(i)
    {
    }
    value_proxy operator*() const
    {
        return {it->first, it->second};
    }
    arrow_proxy operator->() const
    {
        return arrow_proxy{{it->first, it->second}};
    }
    json::object_iterator& operator++()
    {
        ++it;
        return *this;
    }
    json::object_iterator operator++(int)
    {
        auto kv = *this;
        ++(*this);
        return kv;
    }
    bool operator==(const json::object_iterator& rhs) const
    {
        return it == rhs.it;
    }
    bool operator!=(const json::object_iterator& rhs) const
    {
        return !(*this == rhs);
    }
};

inline json::object_iterator json::object_view::begin()
{
    return json::object_iterator(obj->begin());
}

inline json::object_iterator json::object_view::end()
{
    return json::object_iterator(obj->end());
}

}  // namespace tbd

template <>
struct std::iterator_traits<tbd::json::array_iterator>
{
    using iterator_category = std::forward_iterator_tag;
    using value_type = tbd::json;
    using difference_type = std::ptrdiff_t;
    using pointer = tbd::json*;
    using reference = tbd::json&;
};
template <>
struct std::iterator_traits<tbd::json::object_iterator>
{
    using iterator_category = std::input_iterator_tag;
    using value_type = tbd::json::object_iterator::value_proxy;
    using difference_type = std::ptrdiff_t;
    using pointer = tbd::json::object_iterator::arrow_proxy;
    using reference = tbd::json::object_iterator::value_proxy;
};

#endif
