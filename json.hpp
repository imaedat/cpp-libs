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
#include <unordered_map>
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
    void initialize(value_t type, V&& v, union number n = {})
    {
        alloc(type);
        if constexpr (std::is_same_v<std::decay_t<V>, bool>) {
            *to_bool_() = v;
        } else if constexpr (string_like<V>) {
            if (type_ == value_t::unescaped_string) {
                type_ = value_t::string;
                *to_str_() = escape_(v);
            } else {
                *to_str_() = std::forward<V>(v);
                if (type_ == value_t::integral) {
                    *to_int_() = n.i;
                } else if (type_ == value_t::floating) {
                    *to_float_() = n.d;
                }
            }
        } else if constexpr (std::is_same_v<std::decay_t<V>, object_type>) {
            operator=(std::forward<V>(v));
        } else if constexpr (std::is_same_v<std::decay_t<V>, array_type>) {
            operator=(std::forward<V>(v));
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
        initialize(type, std::forward<V>(v), n);
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
            initialize(value_t::boolean, v);
        } else if constexpr (std::is_integral_v<std::decay_t<V>>) {
            n.i = v;
            initialize(value_t::integral, std::to_string(v), n);
        } else if constexpr (std::is_floating_point_v<std::decay_t<V>>) {
            n.d = v;
            initialize(value_t::floating, std::to_string(v), n);
        } else if constexpr (string_like<V>) {
            initialize(value_t::unescaped_string, std::forward<V>(v));
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
            void operator()(std::monostate)
            {
                obj->emplace(k, json(value_t::null));
            }
            void operator()(bool v)
            {
                obj->emplace(k, json(value_t::boolean, v));
            }
            void operator()(int64_t v)
            {
                n.i = v;
                obj->emplace(k, json(value_t::integral, std::to_string(v), n));
            }
            void operator()(double v)
            {
                n.d = v;
                obj->emplace(k, json(value_t::floating, std::to_string(v), n));
            }
            void operator()(const std::string& v)
            {
                obj->emplace(k, json(value_t::unescaped_string, v));
            }
            void operator()(const json& v)
            {
                obj->emplace(k, v);
            }
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
            void operator()(std::monostate)
            {
                arr->emplace_back(json(value_t::null));
            }
            void operator()(bool v)
            {
                arr->emplace_back(json(value_t::boolean, v));
            }
            void operator()(int64_t v)
            {
                n.i = v;
                arr->emplace_back(json(value_t::integral, std::to_string(v), n));
            }
            void operator()(double v)
            {
                n.d = v;
                arr->emplace_back(json(value_t::floating, std::to_string(v), n));
            }
            void operator()(const std::string& v)
            {
                arr->emplace_back(json(value_t::unescaped_string, v));
            }
            void operator()(const json& v)
            {
                arr->emplace_back(v);
            }
        };

        alloc(value_t::array);
        auto* arr = to_arr_();
        for (auto&& v : list) {
            value_visitor vv{arr, {}};
            std::visit(vv, v);
        }
    }
    json(const json& rhs)
    {
        *this = rhs;
    }
    json& operator=(const json& rhs)
    {
        if (this != &rhs) {
            reset();
            type_ = rhs.type_;
            textsize_ = rhs.textsize_;
            switch (type_) {
            case value_t::null:
                break;

            case value_t::boolean:
                new (buffer_) bool(*rhs.to_bool_());
                break;

            case value_t::integral:
            case value_t::floating:
                copy_value(rhs);
                [[fallthrough]];

            case value_t::integral_uncached:
            case value_t::floating_uncached:
            case value_t::string:
                new (buffer_) std::string(*rhs.to_str_());
                break;

            case value_t::object:
                new (buffer_) object_type(*rhs.to_obj_());
                break;

            case value_t::array:
                new (buffer_) array_type(*rhs.to_arr_());
                break;

            default:
                __builtin_unreachable();
            }
        }
        return *this;
    }
    json(json&& rhs) noexcept
    {
        *this = std::move(rhs);
    }
    json& operator=(json&& rhs) noexcept
    {
        if (this != &rhs) {
            reset();
            type_ = rhs.type_;
            textsize_ = rhs.textsize_;
            switch (type_) {
            case value_t::null:
                break;

            case value_t::boolean:
                new (buffer_) bool(*rhs.to_bool_());
                break;

            case value_t::integral:
            case value_t::floating:
                copy_value(rhs);
                [[fallthrough]];

            case value_t::integral_uncached:
            case value_t::floating_uncached:
            case value_t::string:
                new (buffer_) std::string(std::move(*rhs.to_str_()));
                break;

            case value_t::object:
                new (buffer_) object_type(std::move(*rhs.to_obj_()));
                break;

            case value_t::array:
                new (buffer_) array_type(std::move(*rhs.to_arr_()));
                break;

            default:
                __builtin_unreachable();
            }

            rhs.reset();
        }
        return *this;
    }
    ~json()
    {
        reset();
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
        std::ifstream ifs(file.data());
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
            return to_str_()->size();

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
        std::swap(*this, rhs);
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
            auto* self = const_cast<json*>(this);
            if (type_ == value_t::integral_uncached) {
                *self->to_int_() = strtonum<int64_t>();
                self->type_ = value_t::integral;
            } else if (type_ == value_t::floating_uncached) {
                *self->to_float_() = strtonum<double>();
                self->type_ = value_t::floating;
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
                std::tie(it, std::ignore) = obj->emplace(unescape_(key), json{});
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
    struct item_ref;
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
          void* numbuffer_()       { return std::launder(buffer_ + num_offset); }
    const void* numbuffer_() const { return std::launder(buffer_ + num_offset); }

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

    template <typename J, std::enable_if_t<std::is_same_v<std::decay_t<J>, json>, bool> = true>
    void copy_value(J&& j)
    {
        if (is_integer()) {
            *to_int_() = *j.to_int_();
        } else if (is_floating()) {
            *to_float_() = *j.to_float_();
        } else {
            assert(false);
        }
    }

    template <typename T>
    T strtonum() const
    {
        auto* s = to_str_();
        T v{};
        auto [_, ec] = std::from_chars(s->data(), s->data() + s->size(), v);
        if (ec != std::errc{}) {
            throw_invalid(__func__, "invalid numeric: " + *s);
        }
        return v;
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

    static void unescape_utf8(std::string& u, const char*& p)
    {
        const char* start = p;
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
            // XXX unhandled
            u.push_back('\\');
            u.push_back('u');
            u.append(start, 4);
        }
    }

    static unsigned decode_cp(const char*& p)
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

    static char unescape_(char c)
    {
        // XXX invalid/unknown escape sequence?
        switch (c) {
        case 'b':
            return '\b';
        case 'f':
            return '\f';
        case 'n':
            return '\n';
        case 'r':
            return '\r';
        case 't':
            return '\t';
        case '\0':
            throw_invalid(__func__, "unexpected eof");
        default:
            return c;
        }
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
            ltrim();
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
            ltrim(1);
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
                ltrim();
                auto v = parse_value();
                obj->emplace(std::move(*k.to_str_()), std::move(v));

                ltrim((comma = *p_ == ',') ? 1 : 0);
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
            ltrim(1);
            return j;
        }

        json parse_array()
        {
            auto _ = s_.push(__func__);
            assert(*p_ == '[');
            ltrim(1);
            json j(value_t::array);
            auto* arr = j.to_arr_();
            bool comma = false;
            while (*p_ != ']') {
                auto v = parse_value();
                arr->emplace_back(std::move(v));
                ltrim((comma = *p_ == ',') ? 1 : 0);
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
            ltrim(1);
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
                    throw_parser("invalid character");
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
                    }
                    if (is_key) {
                        s.push_back(json::unescape_(c));
                    }
                }
            }
            if (!is_key) {
                s.assign(base, p_ - base - 1);
            }
            ltrim();
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
            ltrim();
            return json(type, std::move(s));
        }

        json parse_literal()
        {
            auto _ = s_.push(__func__);
            if (std::strncmp(p_, "true", 4) == 0) {
                ltrim(4);
                return json(value_t::boolean, true);
            }
            if (std::strncmp(p_, "false", 5) == 0) {
                ltrim(5);
                return json(value_t::boolean, false);
            }
            if (std::strncmp(p_, "null", 4) == 0) {
                ltrim(4);
                return json{};
            }
            throw_parser("unexpected literal");
        }

        void ltrim(ptrdiff_t offset = 0) noexcept
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
struct json::item_ref
{
    const std::string& key;
    json& value;
};

struct json::object_iterator
{
    json::object_type::iterator it;
    explicit object_iterator(json::object_type::iterator i)
        : it(i)
    {
    }
    json::item_ref operator*() const
    {
        return {it->first, it->second};
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

json::object_iterator json::object_view::begin()
{
    return json::object_iterator(obj->begin());
}

json::object_iterator json::object_view::end()
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
    using value_type = tbd::json::item_ref;
    using difference_type = std::ptrdiff_t;
    using pointer = void;
    using reference = tbd::json::item_ref;
};

#endif
