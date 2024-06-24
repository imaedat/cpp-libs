#ifndef SQLITE_HPP_
#define SQLITE_HPP_

#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>

#include <sqlite3.h>

namespace tbd {

class sqlite
{
    class transaction;
    using query_cb_t = std::function<void(int,char**)>;

  public:
    explicit sqlite(std::string_view dbfile)
    {
        int rc = sqlite3_open(dbfile.data(), &db_);
        if (rc != SQLITE_OK) {
            close();
            throw std::runtime_error("sqlite3_open failed");
        }
    }

    sqlite(const sqlite&) = delete;
    sqlite& operator=(const sqlite&) = delete;
    sqlite(sqlite&&) noexcept = default;
    sqlite& operator=(sqlite&&) noexcept = default;

    ~sqlite()
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

    void exec(std::string_view sql)
    {
        exec_(sql, nullptr, nullptr);
    }

    int64_t count(std::string_view sql)
    {
        int64_t count = 0;
        exec_(sql, count_cb, &count);
        return count;
    }

    // `user_cb` called for each row
    void query(std::string_view sql, const query_cb_t& user_cb)
    {
        exec_(sql, query_cb, (void *)&user_cb);
    }

  private:
    sqlite3 *db_ = nullptr;

    void exec_(std::string_view sql, int (*cb)(void*,int,char**,char**), void *args)
    {
        char *mbuf = nullptr;
        int rc = sqlite3_exec(db_, sql.data(), cb, args, &mbuf);
        if (rc != SQLITE_OK) {
            std::string msg("(unknown)");
            if (mbuf) {
                msg = std::string(mbuf);
                sqlite3_free(mbuf);
            }
            throw std::runtime_error("sqlite3_exec failed: " + msg);
        }
    }

    void close()
    {
        sqlite3_close(db_);
        db_ = nullptr;
    }

    static int count_cb(void *count, int ncolumns, char **values, char **names)
    {
        (void)ncolumns;
        (void)names;
        try {
            *(int64_t *)count = std::stoll(values[0]);
        } catch (...) {
            *(int64_t *)count = -1;
        }
        return 0;
    }

    static int query_cb(void *user_cb, int ncolumns, char **values, char **names)
    {
        (void)ncolumns;
        (void)names;
        (*(query_cb_t *)user_cb)(ncolumns, values);
        return 0;
    }

    class transaction
    {
      public:
        transaction(const transaction&) = delete;
        transaction& operator=(const transaction&) = delete;
        transaction(transaction&&) noexcept = default;
        transaction& operator=(transaction&&) noexcept = default;
        ~transaction()
        {
            rollback();
        }

        void exec(std::string_view sql)
        {
            if (!completed_) {
                db_.exec(sql);
            }
        }

        int64_t count(std::string_view sql)
        {
            return completed_ ? -1 : db_.count(sql);
        }

        void query(std::string_view sql, const query_cb_t& user_cb)
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

        void rollback()
        {
            if (!completed_) {
                db_.exec("rollback;");
                completed_ = true;
            }
        }

      private:
        sqlite& db_;
        bool completed_;

        explicit transaction(sqlite& db) noexcept : db_(db), completed_(false) {}

        friend class sqlite;
    };
};

}  // namespace tbd

#endif
