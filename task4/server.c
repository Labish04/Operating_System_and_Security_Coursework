#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <crypt.h>
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
#define USERNAME_MAX   64
#define HASH_MAX       128
#define MAX_USERS      200
#define USERS_FILE     "users.db"
 
pthread_mutex_t log_lock   = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t count_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t users_lock = PTHREAD_MUTEX_INITIALIZER;
int active_clients = 0;
 
static volatile sig_atomic_t running = 1;
static int server_fd_global = -1;
 
typedef struct {
    char username[USERNAME_MAX];
    char hash[HASH_MAX];
} user_record_t;
 
static user_record_t users[MAX_USERS];
static int user_count = 0;
 
void handle_shutdown_signal(int sig)
{
    (void)sig;
    running = 0;
    if (server_fd_global >= 0) shutdown(server_fd_global, SHUT_RDWR);
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
 
/* ---------------------------------------------------------------------
 * User account store: load/save/find, all under users_lock.
 * ------------------------------------------------------------------- */
 
void load_users(void)
{
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return; /* no file yet is fine - fresh install */
 
    char line[USERNAME_MAX + HASH_MAX];
    while (fgets(line, sizeof(line), f) && user_count < MAX_USERS) {
        line[strcspn(line, "\r\n")] = '\0';
        char *sep = strchr(line, ':');
        if (!sep) continue;
        *sep = '\0';
        const char *uname = line;
        const char *hash = sep + 1;
        if (strlen(uname) == 0 || strlen(uname) >= USERNAME_MAX) continue;
        if (strlen(hash) == 0 || strlen(hash) >= HASH_MAX) continue;
 
        strncpy(users[user_count].username, uname, USERNAME_MAX - 1);
        users[user_count].username[USERNAME_MAX - 1] = '\0';
        strncpy(users[user_count].hash, hash, HASH_MAX - 1);
        users[user_count].hash[HASH_MAX - 1] = '\0';
        user_count++;
    }
    fclose(f);
    server_log("[SERVER] Loaded %d user account(s) from %s\n", user_count, USERS_FILE);
}
 
/* Caller must hold users_lock. Returns index or -1. */
int find_user_locked(const char *username)
{
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, username) == 0) return i;
    }
    return -1;
}
 
/* Appends one account to memory + disk. Caller must hold users_lock. */
int add_user_locked(const char *username, const char *hash)
{
    if (user_count >= MAX_USERS) return -1;
 
    strncpy(users[user_count].username, username, USERNAME_MAX - 1);
    users[user_count].username[USERNAME_MAX - 1] = '\0';
    strncpy(users[user_count].hash, hash, HASH_MAX - 1);
    users[user_count].hash[HASH_MAX - 1] = '\0';
    user_count++;
 
    FILE *f = fopen(USERS_FILE, "a");
    if (!f) return -1;
    fprintf(f, "%s:%s\n", username, hash);
    fclose(f);
    return 0;
}
 
/* Builds an MD5-crypt salt string like "$1$abcdEFGH$" using rand_r() with
 * a caller-supplied per-thread seed (avoids sharing RNG state across
 * threads, which plain rand() would do). */
void generate_salt(char *out, size_t outsize, unsigned int *seed)
{
    static const char charset[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    const size_t salt_chars = 8;
 
    snprintf(out, outsize, "$1$");
    size_t pos = strlen(out);
    for (size_t i = 0; i < salt_chars && pos + 1 < outsize - 1; i++, pos++) {
        out[pos] = charset[rand_r(seed) % (sizeof(charset) - 1)];
    }
    out[pos] = '$';
    out[pos + 1] = '\0';
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
    char current_user[USERNAME_MAX] = "";
    line_reader_t reader = { .len = 0 };
    char line[BUF_SIZE];
 
    /* Per-thread crypt_r scratch space and RNG seed - kept on this thread's
     * stack so there is no sharing/contention with other client threads. */
    struct crypt_data cdata;
    cdata.initialized = 0;
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid() ^ (unsigned long)pthread_self());
 
    for (;;) {
        int rc = read_line(fd, &reader, line, sizeof(line));
        if (rc == 0) {
            server_log("[SERVER] Client %s:%d (%s) disconnected\n", ip, port,
                       current_user[0] ? current_user : "unauthenticated");
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
 
        if (strncmp(line, "REGISTER ", 9) == 0) {
            char uname[USERNAME_MAX], pass[USERNAME_MAX];
            if (sscanf(line + 9, "%63s %63s", uname, pass) != 2) {
                snprintf(response, sizeof(response), "ERR:bad_args\n");
            } else {
                pthread_mutex_lock(&users_lock);
                if (find_user_locked(uname) >= 0) {
                    pthread_mutex_unlock(&users_lock);
                    snprintf(response, sizeof(response), "ERR:user_exists\n");
                } else {
                    char salt[16];
                    generate_salt(salt, sizeof(salt), &seed);
                    char *hashed = crypt_r(pass, salt, &cdata);
                    if (!hashed || add_user_locked(uname, hashed) != 0) {
                        pthread_mutex_unlock(&users_lock);
                        snprintf(response, sizeof(response), "ERR:server_full\n");
                    } else {
                        pthread_mutex_unlock(&users_lock);
                        server_log("[SERVER] Registered new account: %s\n", uname);
                        snprintf(response, sizeof(response), "OK:registered\n");
                    }
                }
            }
        } else if (strncmp(line, "LOGIN ", 6) == 0) {
            char uname[USERNAME_MAX], pass[USERNAME_MAX];
            if (sscanf(line + 6, "%63s %63s", uname, pass) != 2) {
                snprintf(response, sizeof(response), "ERR:bad_args\n");
            } else {
                pthread_mutex_lock(&users_lock);
                int idx = find_user_locked(uname);
                if (idx < 0) {
                    pthread_mutex_unlock(&users_lock);
                    snprintf(response, sizeof(response), "ERR:no_such_user\n");
                } else {
                    char stored_hash[HASH_MAX];
                    strncpy(stored_hash, users[idx].hash, HASH_MAX - 1);
                    stored_hash[HASH_MAX - 1] = '\0';
                    pthread_mutex_unlock(&users_lock);
 
                    char *hashed = crypt_r(pass, stored_hash, &cdata);
                    if (hashed && strcmp(hashed, stored_hash) == 0) {
                        authenticated = 1;
                        strncpy(current_user, uname, USERNAME_MAX - 1);
                        current_user[USERNAME_MAX - 1] = '\0';
                        server_log("[SERVER] %s:%d logged in as %s\n", ip, port, uname);
                        snprintf(response, sizeof(response), "OK:login_success:%s\n", uname);
                    } else {
                        snprintf(response, sizeof(response), "ERR:bad_credentials\n");
                    }
                }
            }
        } else if (strncmp(line, "AUTH ", 5) == 0) {
            /* Legacy shared-token path, kept for backward compatibility. */
            if (strcmp(line + 5, VALID_TOKEN) == 0) {
                authenticated = 1;
                snprintf(current_user, sizeof(current_user), "token-user");
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
 
    load_users();
 
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
