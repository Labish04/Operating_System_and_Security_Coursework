#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#define BUF_SIZE       512
#define LINE_BUF_SIZE  1024
#define VALID_TOKEN    "cw-secret-token"
#define BACKLOG        10
#define MAX_CLIENTS    50
#define IDLE_TIMEOUT_S 120

pthread_mutex_t log_lock   = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;
int active_clients = 0;

static volatile sig_atomic_t running = 1;
static int server_fd_global = -1;

void handle_shutdown_signal(int sig)
{
    (void)sig;
    running = 0;
    if (server_fd_global >= 0) {
        shutdown(server_fd_global, SHUT_RDWR);
    }
}

void server_log(const char *fmt, ...)
{
    pthread_mutex_lock(&log_lock);
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
    pthread_mutex_unlock(&log_lock);
}

int validate_input(const char *line)
{
    size_t len = strlen(line);
    if (len == 0 || len >= BUF_SIZE - 1) return 0;
    for (size_t i = 0; i < len; i++) {
        if (line[i] == '\0') return 0;
    }
    return 1;
}

int send_all(int fd, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("send");
            return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

typedef struct {
    int client_fd;
    struct sockaddr_in addr;
} client_ctx_t;

typedef struct {
    char buf[LINE_BUF_SIZE];
    size_t len;
} line_reader_t;

int read_line(int fd, line_reader_t *r, char *out_line, size_t out_size)
{
    for (;;) {
        char *nl = memchr(r->buf, '\n', r->len);
        if (nl) {
            size_t line_len = (size_t)(nl - r->buf);
            size_t copy_len = line_len < out_size - 1 ? line_len : out_size - 1;
            memcpy(out_line, r->buf, copy_len);
            out_line[copy_len] = '\0';
            if (copy_len > 0 && out_line[copy_len - 1] == '\r') out_line[copy_len - 1] = '\0';

            size_t remaining = r->len - line_len - 1;
            memmove(r->buf, nl + 1, remaining);
            r->len = remaining;
            return 1;
        }

        if (r->len >= sizeof(r->buf) - 1) {
            r->len = 0;
            out_line[0] = '\0';
            return 1;
        }

        ssize_t n = recv(fd, r->buf + r->len, sizeof(r->buf) - r->len - 1, 0);
        if (n == 0) return 0;
        if (n < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) return -2;
            if (errno == EINTR) continue;
            perror("recv");
            return -1;
        }
        r->len += (size_t)n;
    }
}

void *handle_client(void *arg)
{
    client_ctx_t *ctx = (client_ctx_t *)arg;
    int fd = ctx->client_fd;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ctx->addr.sin_addr, ip, sizeof(ip));
    int port = ntohs(ctx->addr.sin_port);

    struct timeval tv = { .tv_sec = IDLE_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    pthread_mutex_lock(&count_lock);
    active_clients++;
    int my_count = active_clients;
    pthread_mutex_unlock(&count_lock);
 
    server_log("[SERVER] Client connected %s:%d (active clients: %d)\n", ip, port, my_count);
 
    int authenticated = 0;
    line_reader_t reader = { .len = 0 };
    char line[BUF_SIZE];
 
    for (;;) {
        int rc = read_line(fd, &reader, line, sizeof(line));
        if (rc == 0) {
            server_log("[SERVER] Client %s:%d disconnected\n", ip, port);
            break;
        }
        if (rc == -2) {
            server_log("[SERVER] Client %s:%d idle timeout, closing\n", ip, port);
            const char *msg = "ERR:idle_timeout\n";
            send_all(fd, msg, strlen(msg));
            break;
        }
        if (rc == -1) {
            server_log("[SERVER] Client %s:%d connection error\n", ip, port);
            break;
        }
 
        if (!validate_input(line)) {
            const char *msg = "ERR:invalid_input\n";
            if (send_all(fd, msg, strlen(msg)) < 0) break;
            continue;
        }
 
        server_log("[SERVER] From %s:%d -> \"%s\"\n", ip, port, line);
 
        char response[BUF_SIZE];
        if (strncmp(line, "AUTH ", 5) == 0) {
            if (strcmp(line + 5, VALID_TOKEN) == 0) {
                authenticated = 1;
                snprintf(response, sizeof(response), "OK:authenticated\n");
            } else {
                snprintf(response, sizeof(response), "ERR:bad_token\n");
            }
        } else if (!authenticated) {
            snprintf(response, sizeof(response), "ERR:not_authenticated\n");
        } else if (strncmp(line, "ECHO ", 5) == 0) {
            snprintf(response, sizeof(response), "ECHO:%s\n", line + 5);
        } else if (strncmp(line, "ADD ", 4) == 0) {
            long a, b;
            if (sscanf(line + 4, "%ld %ld", &a, &b) == 2)
                snprintf(response, sizeof(response), "RESULT:%ld\n", a + b);
            else
                snprintf(response, sizeof(response), "ERR:bad_args\n");
        } else if (strcmp(line, "STATS") == 0) {
            pthread_mutex_lock(&count_lock);
            int n = active_clients;
            pthread_mutex_unlock(&count_lock);
            snprintf(response, sizeof(response), "STATS:%d\n", n);
        } else if (strcmp(line, "QUIT") == 0) {
            snprintf(response, sizeof(response), "BYE\n");
            send_all(fd, response, strlen(response));
            break;
        } else {
            snprintf(response, sizeof(response), "ERR:unknown_command\n");
        }

        if (send_all(fd, response, strlen(response)) < 0) break;
    }

    close(fd);
    pthread_mutex_lock(&count_lock);
    active_clients--;
    pthread_mutex_unlock(&count_lock);
    free(ctx);
    return NULL;
}

int main(int argc, char *argv[])
{
    int port = (argc > 1) ? atoi(argv[1]) : 5050;

    signal(SIGINT, handle_shutdown_signal);
    signal(SIGTERM, handle_shutdown_signal);
    signal(SIGPIPE, SIG_IGN);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(1); }
    server_fd_global = server_fd;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(server_fd, BACKLOG) < 0) { perror("listen"); exit(1); }

    server_log("[SERVER] Listening on port %d (TCP)...\n", port);

    while (running) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);

        if (client_fd < 0) {
            if (!running) break;
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }

        pthread_mutex_lock(&count_lock);
        int current = active_clients;
        pthread_mutex_unlock(&count_lock);

        if (current >= MAX_CLIENTS) {
            const char *msg = "ERR:server_busy\n";
            send_all(client_fd, msg, strlen(msg));
            server_log("[SERVER] Rejected connection: MAX_CLIENTS (%d) reached\n", MAX_CLIENTS);
            close(client_fd);
            continue;
        }

        client_ctx_t *ctx = malloc(sizeof(client_ctx_t));
        if (!ctx) { perror("malloc"); close(client_fd); continue; }
        ctx->client_fd = client_fd;
        ctx->addr = client_addr;

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, ctx) != 0) {
            perror("pthread_create");
            close(client_fd);
            free(ctx);
            continue;
        }
        pthread_detach(tid);
    }

    server_log("[SERVER] Shutting down, closing listening socket.\n");
    close(server_fd);
    return 0;
}
