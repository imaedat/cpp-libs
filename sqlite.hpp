#ifndef SQLITE_HPP_
#define SQLITE_HPP_

#include <sqlite3.h>

#include <cstring>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace tbd {

namespace detail {
inline void assert_success(int ec, const std::string& fname)
{
    if (ec != SQLITE_OK) {
        throw std::runtime_error(fname + ": " + sqlite3_errstr(ec));
    }
}
}  // namespace detail

class sqlite
{
    class transaction;
    class cursor;
    class row;
    class field;
    using query_cb_t = std::function<void(int, char**, char**)>;

    class prepared_statement
    {
        sqlite3_stmt* stmt_ = nullptr;

      public:
        prepared_statement() = default;
        prepared_statement(const prepared_statement&) = delete;
        prepared_statement& operator=(const prepared_statement&) = delete;
        prepared_statement(prepared_statement&& rhs) noexcept
            : stmt_(std::exchange(rhs.stmt_, nullptr))
        {
        }
        prepared_statement& operator=(prepared_statement&& rhs) noexcept
        {
            if (this != &rhs) {
                finalize();
                stmt_ = std::exchange(rhs.stmt_, nullptr);
            }
            return *this;
        }
        ~prepared_statement() noexcept
        {
            finalize();
        }

        sqlite3_stmt* operator*() const noexcept
        {
            return stmt_;
        }

        sqlite3_stmt** addr() noexcept
        {
            return &stmt_;
        }

      private:
        void finalize() noexcept
        {
            if (stmt_) {
                (void)sqlite3_finalize(stmt_);
                stmt_ = nullptr;
            }
        }
    };

  public:
    explicit sqlite(std::string_view dbfile = ":memory:")
    {
        int ec = sqlite3_open(dbfile.data(), &db_);
        if (ec != SQLITE_OK) {
            std::string msg(sqlite3_errstr(ec));
            close();
            throw std::runtime_error("sqlite3_open: " + msg);
        }
    }

    sqlite(const sqlite&) = delete;
    sqlite& operator=(const sqlite&) = delete;
    sqlite(sqlite&& rhs) noexcept
        : db_(std::exchange(rhs.db_, nullptr))
    {
    }
    sqlite& operator=(sqlite&& rhs) noexcept
    {
        if (this != &rhs) {
            db_ = std::exchange(rhs.db_, nullptr);
        }
        return *this;
    }

    ~sqlite() noexcept
    {
        close();
    }

    void begin(const std::function<void(transaction&)>& fn)
    {
        transaction txn(*this);

        try {
            exec("begin;");
            fn(txn);
            txn.commit();
        } catch (...) {
            txn.rollback();
            throw;
        }
    }

    struct blob
    {
        const void* ptr;
        int size;
    };

    template <typename... Args>
    int64_t exec(std::string_view sql, Args&&... params) const
    {
        auto stmt = bind_params(sql, std::forward<Args>(params)...);
        auto ec = sqlite3_step(*stmt);
        if (ec != SQLITE_DONE && ec != SQLITE_ROW) {
            throw std::runtime_error(std::string("sqlite3_step: ") + sqlite3_errstr(ec));
        }
        return sqlite3_changes(db_);
    }

    template <typename... Args>
    cursor cursor_for(std::string_view sql, Args&&... params) const
    {
        auto stmt = bind_params(sql, std::forward<Args>(params)...);
        return cursor(std::move(stmt));
    }

    int64_t exec(std::string_view sql) const
    {
        return exec_(sql, nullptr, nullptr);
    }

    int64_t count(std::string_view sql) const
    {
        int64_t count = 0;
        exec_(sql, count_cb, &count);
        return count;
    }

    // `user_cb` called for each row
    void query(std::string_view sql, const query_cb_t& user_cb) const
    {
        exec_(sql, query_cb, (void*)&user_cb);
    }

    cursor cursor_for(std::string_view sql) const
    {
        prepared_statement stmt;
        auto ec = sqlite3_prepare_v2(db_, sql.data(), -1, stmt.addr(), 0);
        detail::assert_success(ec, "sqlite3_prepare_v2");
        return cursor(std::move(stmt));
    }

  private:
    sqlite3* db_ = nullptr;

    void close() noexcept
    {
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
    }

    template <typename... Args>
    prepared_statement bind_params(std::string_view sql, Args&&... params) const
    {
        prepared_statement stmt;
        auto ec = sqlite3_prepare_v2(db_, sql.data(), -1, stmt.addr(), 0);
        detail::assert_success(ec, "sqlite3_prepare_v2");
        int index = 0;
        (..., bind(stmt, index, std::forward<Args>(params)));
        return stmt;
    }

    template <typename I, std::enable_if_t<std::is_integral_v<I>, bool> = true>
    void bind(prepared_statement& stmt, int& index, I num) const
    {
        auto ec = sqlite3_bind_int64(*stmt, ++index, num);
        detail::assert_success(ec, "sqlite3_bind_int64");
    }

    template <typename F, std::enable_if_t<std::is_floating_point_v<F>, bool> = true>
    void bind(prepared_statement& stmt, int& index, F num) const
    {
        auto ec = sqlite3_bind_double(*stmt, ++index, num);
        detail::assert_success(ec, "sqlite3_bind_double");
    }

    void bind(prepared_statement& stmt, int& index, const char* str) const
    {
        auto ec = sqlite3_bind_text(*stmt, ++index, str, -1, SQLITE_STATIC);
        detail::assert_success(ec, "sqlite3_bind_text");
    }

    void bind(prepared_statement& stmt, int& index, const std::string& str) const
    {
        auto ec = sqlite3_bind_text(*stmt, ++index, str.data(), str.size(), SQLITE_STATIC);
        detail::assert_success(ec, "sqlite3_bind_text");
    }

    void bind(prepared_statement& stmt, int& index, std::string&& str) const
    {
        auto ec = sqlite3_bind_text(*stmt, ++index, str.data(), str.size(), SQLITE_TRANSIENT);
        detail::assert_success(ec, "sqlite3_bind_text");
    }

    void bind(prepared_statement& stmt, int& index, const blob& blob) const
    {
        auto ec = sqlite3_bind_blob(*stmt, ++index, blob.ptr, blob.size, SQLITE_STATIC);
        detail::assert_success(ec, "sqlite3_bind_blob");
    }

    int64_t exec_(std::string_view sql, int (*cb)(void*, int, char**, char**), void* args) const
    {
        char* mbuf = nullptr;
        int ec = sqlite3_exec(db_, sql.data(), cb, args, &mbuf);
        if (ec != SQLITE_OK) {
            std::string msg("(unknown)");
            if (mbuf) {
                msg = std::string(mbuf);
                sqlite3_free(mbuf);
            }
            throw std::runtime_error("sqlite3_exec: " + msg);
        }
        return sqlite3_changes(db_);
    }

    static int count_cb(void* count, int ncolumns, char** values, char** names) noexcept
    {
        (void)ncolumns;
        (void)names;
        try {
            *(int64_t*)count = std::stoll(values[0]);
        } catch (...) {
            *(int64_t*)count = -1;
        }
        return 0;
    }

    static int query_cb(void* user_cb, int ncolumns, char** values, char** names)
    {
        (void)ncolumns;
        (void)names;
        (*(query_cb_t*)user_cb)(ncolumns, values, names);
        return 0;
    }

    /************************************************************************
     * transaction
     */
    class transaction
    {
      public:
        transaction(const transaction&) = delete;
        transaction& operator=(const transaction&) = delete;
        transaction(transaction&& rhs) noexcept
            : db_(rhs.db_)
            , completed_(std::exchange(rhs.completed_, true))
        {
        }
        transaction& operator=(transaction&& rhs) noexcept
        {
            if (this != &rhs) {
                db_ = std::move(rhs.db_);
                completed_ = std::exchange(rhs.completed_, true);
            }
            return *this;
        }

        ~transaction() noexcept
        {
            rollback();
        }

        template <typename... Args>
        int64_t exec(std::string_view sql, Args&&... params) const
        {
            if (!completed_) {
                return db_.exec(sql, std::forward<Args>(params)...);
            }
            return -1;
        }

        int64_t exec(std::string_view sql) const
        {
            if (!completed_) {
                return db_.exec(sql);
            }
            return -1;
        }

        int64_t count(std::string_view sql) const
        {
            return completed_ ? -1 : db_.count(sql);
        }

        void query(std::string_view sql, const query_cb_t& user_cb) const
        {
            if (!completed_) {
                db_.query(sql, user_cb);
            }
        }

        void commit()
        {
            if (!completed_) {
                db_.exec("commit;");
                completed_ = true;
            }
        }

        void rollback() noexcept
        {
            if (!completed_) {
                try {
                    db_.exec("rollback;");
                    completed_ = true;
                } catch (const std::exception& e) {
                    fprintf(stderr, "transaction::rollback failed: %s\n", e.what());
                    std::terminate();
                }
            }
        }

      private:
        sqlite& db_;
        bool completed_;

        explicit transaction(sqlite& db) noexcept
            : db_(db)
            , completed_(false)
        {
        }

        friend class sqlite;
    };

    /************************************************************************
     * cursor
     */
    using column_types = std::variant<int64_t, double, const char*, blob>;
    class cursor
    {
      public:
        cursor(const cursor&) = delete;
        cursor& operator=(const cursor&) = delete;
        cursor(cursor&& rhs) noexcept = default;
        cursor& operator=(cursor&& rhs) noexcept = default;
        ~cursor() noexcept = default;

        std::optional<const row> next()
        {
            auto ec = sqlite3_step(*stmt_);

            if (ec == SQLITE_DONE) {
                return std::nullopt;
            }

            if (ec != SQLITE_ROW) {
                std::string msg(sqlite3_errstr(ec));
                throw std::runtime_error("sqlite3_step: " + msg);
            }

            auto ncols = sqlite3_data_count(*stmt_);
            const char* names[ncols];
            column_types values[ncols];
            for (auto i = 0; i < ncols; ++i) {
                names[i] = sqlite3_column_name(*stmt_, i);

                switch (sqlite3_column_type(*stmt_, i)) {
                case SQLITE_INTEGER:
                    values[i] = (int64_t)sqlite3_column_int64(*stmt_, i);
                    break;
                case SQLITE_FLOAT:
                    values[i] = sqlite3_column_double(*stmt_, i);
                    break;
                case SQLITE_TEXT:
                    values[i] = (const char*)sqlite3_column_text(*stmt_, i);
                    break;
                case SQLITE_BLOB:
                    values[i] =
                        blob{sqlite3_column_blob(*stmt_, i), sqlite3_column_bytes(*stmt_, i)};
                    break;
                case SQLITE_NULL:
                    values[i] = "";
                    break;
                default:
                    break;
                }
            }
            return row(ncols, names, values);
        }

      private:
        prepared_statement stmt_;

        cursor(prepared_statement&& stmt)
            : stmt_(std::move(stmt))
        {
        }

        friend class sqlite;
    };

    /************************************************************************
     * row
     */
    class row
    {
      private:
        std::vector<field> fields_;
        using iterator = typename decltype(fields_)::const_iterator;

        row(size_t ncols, const char** names, const column_types* values)
        {
            fields_.reserve(ncols);
            for (size_t i = 0; i < ncols; ++i) {
                field f(names[i], values[i]);
                fields_.push_back(std::move(f));
            }
        }

        friend class cursor;

      public:
        const iterator begin() const
        {
            return fields_.cbegin();
        }

        const iterator end() const
        {
            return fields_.cend();
        }

        const field& operator[](size_t index) const
        {
            return fields_.at(index);
        }

        const field& operator[](std::string_view name) const
        {
            for (const auto& f : fields_) {
                if (f.name() == name) {
                    return f;
                }
            }

            throw std::out_of_range("");
        }

        size_t column_count() const noexcept
        {
            return fields_.size();
        }
    };

    /************************************************************************
     * field
     */
    class field
    {
        using field_types = std::variant<int64_t, double, std::string, std::vector<uint8_t>>;

      public:
        const std::string& name() const noexcept
        {
            return name_;
        }

        int64_t to_i() const
        {
            return std::get<int64_t>(value_);
        }

        double to_f() const
        {
            return std::get<double>(value_);
        }

        const std::string& to_s() const
        {
            return std::get<std::string>(value_);
        }

        const std::vector<uint8_t>& to_b() const
        {
            return std::get<std::vector<uint8_t>>(value_);
        }

      private:
        std::string name_;
        field_types value_;

        explicit field(const char* name, const column_types& value)
            : name_(name)
        {
            switch (value.index()) {
            case 0:  // int64_t
                value_ = std::get<0>(value);
                break;
            case 1:  // double
                value_ = std::get<1>(value);
                break;
            case 2:  // const char *
                value_ = std::get<2>(value);
                break;
            case 3: {  // blob
                const auto& blob = std::get<3>(value);
                std::vector<uint8_t> buf(blob.size);
                ::memcpy(buf.data(), blob.ptr, blob.size);
                value_ = std::move(buf);
                break;
            }
            }
        }

        friend class row;
    };
};

}  // namespace tbd

#endif
