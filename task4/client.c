#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <termios.h>
#include <arpa/inet.h>
#include <sys/socket.h>
 
#define BUF_SIZE 512
#define INPUT_MAX (BUF_SIZE - 8) /* leaves room for the "ECHO " prefix + newline */
 
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
 
/* Sends one line (a newline is appended) and prints whatever the server
 * sends back. Returns 0 on success, -1 if the connection should be
 * considered dead. */
int send_and_receive(int fd, const char *msg, char *reply_out, size_t reply_size)
{
    char out[BUF_SIZE];
    int written = snprintf(out, sizeof(out), "%s\n", msg);
    if (written < 0 || (size_t)written >= sizeof(out)) {
        fprintf(stderr, "[CLIENT] message too long, skipped: %s\n", msg);
        return -1;
    }
 
    if (send_all(fd, out, strlen(out)) < 0) return -1;
 
    char in[BUF_SIZE];
    ssize_t n = recv(fd, in, sizeof(in) - 1, 0);
    if (n == 0) {
        printf("[CLIENT] server closed connection\n");
        return -1;
    }
    if (n < 0) {
        perror("recv");
        return -1;
    }
    in[n] = '\0';
    if (reply_out) snprintf(reply_out, reply_size, "%s", in);
    return 0;
}
 
/* Reads a line from stdin with terminal echo turned off, so passwords
 * aren't shown on screen. Restores echo before returning, including on
 * the error path. */
void read_hidden_line(char *out, size_t out_size)
{
    struct termios oldt, newt;
    int have_termios = (tcgetattr(STDIN_FILENO, &oldt) == 0);
 
    if (have_termios) {
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
 
    if (!fgets(out, (int)out_size, stdin)) out[0] = '\0';
    out[strcspn(out, "\r\n")] = '\0';
 
    if (have_termios) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        printf("\n"); /* the newline the hidden Enter keypress didn't echo */
    }
}
 
/* Returns 1 on a line read, 0 on EOF/error (out is set to "" in that case). */
int read_visible_line(char *out, size_t out_size)
{
    if (!fgets(out, (int)out_size, stdin)) { out[0] = '\0'; return 0; }
    out[strcspn(out, "\r\n")] = '\0';
    return 1;
}
 
/* Returns 1 if `line` already starts with a known protocol command word,
 * so the interactive loop knows whether to wrap free text as ECHO. */
int is_known_command(const char *line)
{
    static const char *commands[] = {
        "REGISTER ", "LOGIN ", "AUTH ", "ECHO ", "ADD ", "STATS", "QUIT"
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        size_t clen = strlen(commands[i]);
        if (strncmp(line, commands[i], clen) == 0) return 1;
        if (strcmp(commands[i], line) == 0) return 1; /* exact match, e.g. "STATS" */
    }
    return 0;
}
 
/* Interactive REGISTER/LOGIN + free-form message loop. */
void run_interactive(int fd)
{
    char username[64], password[64], choice[16], line[INPUT_MAX], reply[BUF_SIZE];
 
    for (;;) {
        printf("\n1) Register\n2) Login\nChoose an option: ");
        fflush(stdout);
        if (!read_visible_line(choice, sizeof(choice))) { printf("\n[CLIENT] input closed, exiting.\n"); return; }
 
        if (strcmp(choice, "1") != 0 && strcmp(choice, "2") != 0) {
            printf("Please enter 1 or 2.\n");
            continue;
        }
 
        printf("Username: ");
        fflush(stdout);
        if (!read_visible_line(username, sizeof(username))) { printf("\n[CLIENT] input closed, exiting.\n"); return; }
 
        printf("Password: ");
        fflush(stdout);
        read_hidden_line(password, sizeof(password));
 
        if (strchr(username, ' ') || strchr(password, ' ') ||
            strlen(username) == 0 || strlen(password) == 0) {
            printf("Username and password can't be empty or contain spaces.\n");
            continue;
        }
 
        snprintf(line, sizeof(line), "%s %s %s",
                 strcmp(choice, "1") == 0 ? "REGISTER" : "LOGIN",
                 username, password);
 
        if (send_and_receive(fd, line, reply, sizeof(reply)) < 0) return;
        printf("Server: %s", reply);
 
        if (strncmp(reply, "OK:login_success", strlen("OK:login_success")) == 0) {
            break; /* logged in, move on to the free-typing loop */
        }
        if (strncmp(reply, "OK:registered", strlen("OK:registered")) == 0) {
            printf("Registered! Now log in with the same credentials.\n");
            continue;
        }
        /* ERR:user_exists, ERR:bad_credentials, ERR:no_such_user, etc. */
        printf("Try again.\n");
    }
 
    printf("\nLogged in. Type any message to send it (plain text is sent as\n"
           "ECHO automatically). Try ADD 2 3, STATS, or QUIT to exit.\n\n");
 
    char input[INPUT_MAX];
    for (;;) {
        printf("> ");
        fflush(stdout);
        if (!read_visible_line(input, sizeof(input))) { printf("\n[CLIENT] input closed, exiting.\n"); break; }
        if (strlen(input) == 0) continue;
 
        char to_send[BUF_SIZE];
        if (is_known_command(input)) {
            snprintf(to_send, sizeof(to_send), "%s", input);
        } else {
            snprintf(to_send, sizeof(to_send), "ECHO %s", input);
        }
 
        if (send_and_receive(fd, to_send, reply, sizeof(reply)) < 0) return;
        printf("Server: %s", reply);
 
        if (strcmp(input, "QUIT") == 0) break;
    }
}
 
/* The original fixed script, kept available via --demo for repeatable
 * automated testing (e.g. capturing report screenshots, concurrency
 * demos with multiple client processes). */
void run_demo(int fd, int client_id)
{
    char reply[BUF_SIZE];
    send_and_receive(fd, "ECHO too_early", reply, sizeof(reply));
    printf("[CLIENT] reply: %s", reply);
    send_and_receive(fd, "AUTH wrong-token", reply, sizeof(reply));
    printf("[CLIENT] reply: %s", reply);
    send_and_receive(fd, "AUTH cw-secret-token", reply, sizeof(reply));
    printf("[CLIENT] reply: %s", reply);
 
    char echo_msg[64];
    snprintf(echo_msg, sizeof(echo_msg), "ECHO hello_from_client_%d", client_id);
    send_and_receive(fd, echo_msg, reply, sizeof(reply));
    printf("[CLIENT] reply: %s", reply);
 
    send_and_receive(fd, "ADD 15 27", reply, sizeof(reply));
    printf("[CLIENT] reply: %s", reply);
    send_and_receive(fd, "ADD not_a_number", reply, sizeof(reply));
    printf("[CLIENT] reply: %s", reply);
    send_and_receive(fd, "STATS", reply, sizeof(reply));
    printf("[CLIENT] reply: %s", reply);
    send_and_receive(fd, "QUIT", reply, sizeof(reply));
    printf("[CLIENT] reply: %s", reply);
}
 
int main(int argc, char *argv[])
{
    int demo_mode = (argc > 1 && strcmp(argv[1], "--demo") == 0);
    int arg_offset = demo_mode ? 1 : 0;
 
    const char *server_ip = (argc > arg_offset + 1) ? argv[arg_offset + 1] : "127.0.0.1";
    int port = (argc > arg_offset + 2) ? atoi(argv[arg_offset + 2]) : 5050;
    int client_id = (argc > arg_offset + 3) ? atoi(argv[arg_offset + 3]) : 1;
 
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); exit(1); }
 
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) != 1) {
        fprintf(stderr, "[CLIENT] invalid server IP: %s\n", server_ip);
        close(fd);
        exit(1);
    }
 
    if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(fd);
        exit(1);
    }
    printf("[CLIENT #%d] connected to %s:%d\n", client_id, server_ip, port);
 
    if (demo_mode) {
        run_demo(fd, client_id);
    } else {
        run_interactive(fd);
    }
 
    close(fd);
    printf("[CLIENT #%d] connection closed.\n", client_id);
    return 0;
}
