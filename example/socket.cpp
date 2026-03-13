#define SOCKET_USE_OPENSSL
//#define SOCKET_VERBOSE
#include "socket.hpp"

#include <signal.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <cstdio>

#include "logger.hpp"
#include "thread_pool.hpp"

using namespace std;
using namespace tbd;

logger con("socket", "/dev/stdout");

void cloop(connector& cli)
{
    auto l = cli.local_endpoint();
    auto r = cli.remote_endpoint();
    con.info("client : connection from %s to %s", l.to_string().c_str(), r.to_string().c_str());
    usleep(50 * 1000);
    for (int i = 0; i < 10; ++i) {
        auto ret = cli.send(to_string(i));
        if (!ret) {
            con.info("client : send error: %s", ret.message().c_str());
            break;
        }
    }
    con.info("client : done");
    cli.close();
}

void sloop(io_socket& sess)
{
    auto peer = sess.remote_endpoint();
    con.info("server : new connection accepted from %s", peer.to_string().c_str());

    while (true) {
        char buf[128] = {0};
        auto ret = sess.recv_some(buf, 1);
        if (!ret) {
            con.info("session: receive error: %s", ret.message().c_str());
            break;
        }
        con.info("session: recv [%s]", buf);
    }
    con.info("server : done");
}

void c2s(connector& cli, acceptor& srv)
{
    thread_pool pool(1);

    pool.submit([&srv] {
        auto sess = srv.accept();
        sloop(sess);
    });

    usleep(500 * 1000);

    cli.connect();
    cloop(cli);
}

void c2s_nb(connector& cli, acceptor& srv)
{
    thread_pool pool(1);

    pool.submit([&srv] {
        int nacpt = 0;
        while (true) {
            auto sess = srv.accept_nb();
            ++nacpt;
            if (!sess) {
                continue;
            }
            con.info("server : nacpt=%d", nacpt);
            sloop(sess);
            break;
        }
    });

    int nconn = 0;
    while (!cli.connect_nb()) {
        ++nconn;
    }
    con.info("client : nconn=%d", ++nconn);
    cloop(cli);
}

int main()
{
    signal(SIGPIPE, SIG_IGN);

    ssl_ctx srv_ctx(true);
    srv_ctx.load_certificate("hostcert.pem", "hostkey.pem");

    ssl_ctx cli_ctx;
    cli_ctx.load_ca_file("cacert.pem");

    unique_ptr<connector> cli;
    unique_ptr<acceptor> srv;

    puts("--- tcp / blocking ---");
    cli = make_unique<tcp_client>("127.0.0.1", 8080);
    srv = make_unique<tcp_server>(8080);
    c2s(*cli, *srv);

    puts("--- tls / blocking ---");
    cli = make_unique<tls_client>(cli_ctx, "127.0.0.1", 8443);
    srv = make_unique<tls_server>(srv_ctx, 8443);
    c2s(*cli, *srv);

    puts("--- tcp / non-blocking ---");
    cli = make_unique<tcp_client>("127.0.0.1", 8080);
    srv = make_unique<tcp_server>(8080);
    c2s_nb(*cli, *srv);

    puts("--- tls / non-blocking ---");
    cli = make_unique<tls_client>(cli_ctx, "127.0.0.1", 8443);
    srv = make_unique<tls_server>(srv_ctx, 8443);
    c2s_nb(*cli, *srv);

    return 0;
}
