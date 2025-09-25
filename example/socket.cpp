#define SOCKET_USE_OPENSSL
#include "socket.hpp"

#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <cstdio>

#include "thread_pool.hpp"

using namespace std;
using namespace std::chrono;
using namespace tbd;

inline char* now()
{
    thread_local char buf[32] = {0};

    auto count = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
    auto sec = count / (1000 * 1000);
    auto usec = count % (1000 * 1000);
    struct tm tm;
    localtime_r(&sec, &tm);
    strftime(buf, 21, "%F %T.", &tm);
    sprintf(buf + 20, "%06ld", usec);
    return buf;
}

#if 1
#    define LOG(fmt, ...) printf("%s [%04ld] " fmt, now(), syscall(SYS_gettid), ##__VA_ARGS__)
#else
#    define LOG(fmt, ...)
#endif

void cloop(connector& cli)
{
    auto [host, lport] = cli.local_endpoint();
    auto [peer, rport] = cli.remote_endpoint();
    LOG("client : connection from %s:%u to %s:%u\n", host.c_str(), lport, peer.c_str(), rport);
    usleep(50 * 1000);
    for (int i = 0; i < 10; ++i) {
        auto ec = cli.send(to_string(i));
        if (ec) {
            LOG("client : send error: %s\n", ec.message().c_str());
            break;
        }
    }
    LOG("client : done\n");
    cli.close();
}

void sloop(io_socket& sess)
{
    auto [peer, port] = sess.remote_endpoint();
    LOG("server : new connection accepted from %s:%u\n", peer.c_str(), port);

    while (true) {
        char buf[128] = {0};
        auto ec = sess.recv_some(buf, 1);
        if (ec) {
            LOG("session: receive error: %s\n", ec.message().c_str());
            break;
        }
        LOG("session: recv [%s]\n", buf);
    }
    LOG("server : done\n");
}

void c2s(unique_ptr<connector>& cli, unique_ptr<acceptor>& svr)
{
    thread_pool pool(1);

    pool.submit([&svr] {
        auto sess = svr->accept();
        sloop(sess);
    });

    usleep(500 * 1000);

    cli->connect();
    cloop(*cli);
}

void c2s_nb(unique_ptr<connector>& cli, unique_ptr<acceptor>& svr)
{
    thread_pool pool(1);

    pool.submit([&svr] {
        int nacpt = 0;
        while (true) {
            auto sess = svr->accept_nb();
            ++nacpt;
            if (!sess) {
                continue;
            }
            LOG("server : nacpt=%d\n", nacpt);
            sloop(sess);
            break;
        }
    });

    int nconn = 0;
    while (!cli->connect_nb()) {
        ++nconn;
    }
    LOG("client : nconn=%d\n", ++nconn);
    cloop(*cli);
}

int main()
{
    signal(SIGPIPE, SIG_IGN);

    ssl_ctx svr_ctx(true);
    svr_ctx.load_certificate("hostcert.pem", "hostkey.pem");

    ssl_ctx cli_ctx;
    cli_ctx.load_ca_file("cacert.pem");

    unique_ptr<connector> cli;
    unique_ptr<acceptor> svr;

    puts("--- tcp / blocking ---");
    cli = make_unique<tcp_client>("127.0.0.1", 8080);
    svr = make_unique<tcp_server>(8080);
    c2s(cli, svr);

    puts("--- tls / blocking ---");
    cli = make_unique<tls_client>(cli_ctx, "127.0.0.1", 8443);
    svr = make_unique<tls_server>(svr_ctx, 8443);
    c2s(cli, svr);

    puts("--- tcp / non-blocking ---");
    cli = make_unique<tcp_client>("127.0.0.1", 8080);
    svr = make_unique<tcp_server>(8080);
    c2s_nb(cli, svr);

    puts("--- tls / non-blocking ---");
    cli = make_unique<tls_client>(cli_ctx, "127.0.0.1", 8443);
    svr = make_unique<tls_server>(svr_ctx, 8443);
    c2s_nb(cli, svr);

    return 0;
}
