#include "sqlite.hpp"

#include <time.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace tbd;
using namespace std;
using namespace std::chrono;
using systime = system_clock::time_point;

namespace {
// milliseconds string -> time_point
systime millistr2tp(string_view t)
{
    struct tm tm;
    auto p = strptime(t.data(), "%F %T.", &tm);
    return systime(milliseconds(timegm(&tm) * 1000 + stoi(p)));
}

// time_point -> milliseconds string
string tp2millistr(systime tp)
{
    auto msec_count = duration_cast<milliseconds>(tp.time_since_epoch()).count();
    auto sec = msec_count / 1000;
    auto msec = msec_count % 1000;
    struct tm tm;
    gmtime_r(&sec, &tm);
    char buf[32] = {0};
    strftime(buf, sizeof(buf), "%F %T.", &tm);
    ostringstream ss;
    ss << buf << setw(3) << setfill('0') << msec;
    return ss.str();
}
}  // namespace

struct record
{
    int64_t id;
    string name;
    systime timestamp;

    record() = default;
    record(char* i, char* n, char* t)
        : id(stoll(i))
        , name(n)
        , timestamp(millistr2tp(t))
    {
        //
    }

    string to_string() const
    {
        ostringstream ss;
        ss << "[" << id << "] " << name << " (" << tp2millistr(timestamp) << ")";
        return ss.str();
    }
};

#define INSERT_INTO "insert into testtab (name, word, timestamp) values"
#define CURRENT_TIMESTAMP "strftime('%Y-%m-%d %H:%M:%f', 'now', 'localtime')"

int main()
{
    sqlite db;

    db.exec("drop table if exists testtab;");
    db.exec("create table if not exists testtab ("
            "  id integer not null primary key autoincrement,"
            "  name text not null,"
            "  word text,"
            "  timestamp text not null"
            ");");
    db.exec("create index if not exists idx_test1_id on testtab (id);");
    db.exec("create index if not exists idx_test1_name on testtab (name);");

    db.begin([](auto& txn) {
        txn.exec(INSERT_INTO "('foo','blah'," CURRENT_TIMESTAMP ")");
        usleep(950);
        txn.exec(INSERT_INTO "('bar','blah blah'," CURRENT_TIMESTAMP ")");
        usleep(950);
        txn.exec(INSERT_INTO "('baz','blax'," CURRENT_TIMESTAMP ")");
        usleep(950);
        txn.exec("insert into testtab (name, timestamp) values ('qux'," CURRENT_TIMESTAMP ")");
    });

    auto count = db.count("select count(*) from testtab;");

    // callback style
    vector<record> records;
    records.reserve(count);
    db.query("select * from testtab order by id;",
             [&records](int ncolumns, char** columns, char** names) {
                 // callback per each row
                 (void)ncolumns;
                 (void)names;
                 records.emplace_back(columns[0], columns[1], columns[3]);
             });
    for (const auto& r : records) {
        cout << r.to_string() << endl;
    }

    puts("---");

    // cursor style
    auto cur = db.cursor_for("select id, name, word, timestamp from testtab order by name;");
    while (true) {
        auto row_opt = cur.next();
        if (!row_opt) {
            break;
        }
        const auto& row = *row_opt;
        cout << "#cols=" << row.column_count() << ": ";
        cout << row[0].name() << "=" << row[0].to_i() << " ";
        cout << row[1].name() << "=" << row[1].to_s() << " ";
        cout << row[2].name() << "=" << row[2].to_s() << " ";
        cout << row[3].name() << "=" << row[3].to_s() << " ";
        cout << endl;
    }

    puts("---");

    auto cur2 = db.cursor_for(
        "select id, name, word, timestamp from testtab where id <= ? or name = ? or word like ?;",
        1, "qux", "blah%");
    while (true) {
        auto row_opt = cur2.next();
        if (!row_opt) {
            break;
        }
        const auto& row = *row_opt;
        cout << "#cols=" << row.column_count() << ": ";
        cout << row[0].name() << "=" << row[0].to_i() << " ";
        cout << row[1].name() << "=" << row[1].to_s() << " ";
        cout << row[2].name() << "=" << row[2].to_s() << " ";
        cout << row[3].name() << "=" << row[3].to_s() << " ";
        cout << endl;
    }

    return 0;
}
