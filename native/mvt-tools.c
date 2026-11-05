#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define TOOLS_VERSION "1.0.0"
#define HASH_BUF_SIZE 65536
#define AUTORUN_SCRIPT "/opt/mvt/bin/mvt-autorun.sh"
#define WATCHER_LOG_FILE "/opt/mvt/logs/mvt-watcher.log"

static volatile sig_atomic_t g_interrupted = 0;

static void handle_sigint(int sig) {
    (void)sig;
    g_interrupted = 1;
}

/* ========================================================================= */
/* SHA-256 Native Hasher Component (mvt-hash)                                */
/* ========================================================================= */

static int hash_fd(int fd, unsigned char *out_digest) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    unsigned char *buf = malloc(HASH_BUF_SIZE);
    if (!buf) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    int status = 0;
    while (!g_interrupted) {
        ssize_t n = read(fd, buf, HASH_BUF_SIZE);
        if (n < 0) {
            if (errno == EINTR) continue;
            status = -1;
            break;
        }
        if (n == 0) break;
        if (EVP_DigestUpdate(ctx, buf, (size_t)n) != 1) {
            status = -1;
            break;
        }
    }

    if (g_interrupted) status = -1;

    unsigned int len = 0;
    if (status == 0 && (EVP_DigestFinal_ex(ctx, out_digest, &len) != 1 || len != 32)) {
        status = -1;
    }

    free(buf);
    EVP_MD_CTX_free(ctx);
    return status;
}

static int hash_file(const char *path, unsigned char *out_digest, bool allow_stdin) {
    int fd;
    bool use_stdin = allow_stdin && strcmp(path, "-") == 0;
    if (use_stdin) {
        fd = STDIN_FILENO;
    } else {
        do {
            fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        } while (fd < 0 && errno == EINTR);
        if (fd < 0) return -1;
        struct stat info;
        int status;
        do {
            status = fstat(fd, &info);
        } while (status < 0 && errno == EINTR);
        if (status < 0 || !S_ISREG(info.st_mode)) {
            int saved = status < 0 ? errno : EINVAL;
            close(fd);
            errno = saved;
            return -1;
        }
    }

    int res = hash_fd(fd, out_digest);
    if (!use_stdin && close(fd) < 0) res = -1;
    return res;
}

static int write_all(const void *data, size_t size) {
    const unsigned char *cursor = data;
    while (size > 0) {
        ssize_t count = write(STDOUT_FILENO, cursor, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            fprintf(stderr, "mvt-hash: cannot write output: %s\n",
                    count < 0 ? strerror(errno) : "zero-length write");
            return -1;
        }
        cursor += count;
        size -= (size_t)count;
    }
    return 0;
}

static int hash_stdin_paths(void) {
    unsigned char input[HASH_BUF_SIZE];
    char path[PATH_MAX];
    size_t used = 0;
    for (;;) {
        if (g_interrupted) {
            fprintf(stderr, "mvt-hash: filename input interrupted\n");
            return 1;
        }
        ssize_t count = read(STDIN_FILENO, input, sizeof(input));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0 || g_interrupted) {
            fprintf(stderr, "mvt-hash: cannot read filename input\n");
            return 1;
        }
        if (count == 0) {
            if (used != 0) {
                fprintf(stderr, "mvt-hash: filename input is not NUL-terminated\n");
                return 1;
            }
            return 0;
        }
        for (ssize_t i = 0; i < count; ++i) {
            if (input[i] == '\0') {
                if (used == 0) {
                    fprintf(stderr, "mvt-hash: empty filename in input\n");
                    return 1;
                }
                path[used] = '\0';
                unsigned char digest[32];
                if (hash_file(path, digest, false) != 0) {
                    fprintf(stderr, "mvt-hash: cannot hash '%s': %s\n", path, strerror(errno));
                    return 1;
                }
                static const char digits[] = "0123456789abcdef";
                char hex[65];
                for (size_t j = 0; j < 32; ++j) {
                    hex[j * 2] = digits[digest[j] >> 4];
                    hex[j * 2 + 1] = digits[digest[j] & 15];
                }
                hex[64] = '\0';
                if (write_all(hex, sizeof(hex)) < 0) return 1;
                used = 0;
            } else {
                if (used == sizeof(path) - 1) {
                    fprintf(stderr, "mvt-hash: input filename is too long\n");
                    return 1;
                }
                path[used++] = (char)input[i];
            }
        }
    }
}

static void print_hash(const unsigned char *digest, const char *path) {
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("  %s\n", path);
}

static int process_path(const char *path) {
    unsigned char digest[32];
    if (hash_file(path, digest, true) != 0) {
        if (errno != 0) {
            fprintf(stderr, "mvt-hash: %s: %s\n", path, strerror(errno));
        } else {
            fprintf(stderr, "mvt-hash: %s: hashing failed\n", path);
        }
        return 1;
    }
    print_hash(digest, path);
    if (fflush(stdout) == EOF || ferror(stdout)) {
        fprintf(stderr, "mvt-hash: cannot write output\n");
        return 1;
    }
    return 0;
}

static int self_test(void) {
    static const unsigned char expected_empty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    unsigned char digest[32];
    int pfd[2];
    if (pipe(pfd) != 0) return -1;
    close(pfd[1]);
    int res = hash_fd(pfd[0], digest);
    close(pfd[0]);
    if (res != 0) return -1;
    if (memcmp(digest, expected_empty, 32) != 0) return -1;
    return 0;
}

static int cmd_hash_main(int argc, char **argv) {
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        fprintf(stderr, "mvt-hash: cannot configure SIGPIPE\n");
        return 1;
    }
    if (argc == 4 && strcmp(argv[1], "--files0-from") == 0 &&
        strcmp(argv[2], "-") == 0 && strcmp(argv[3], "--zero") == 0) {
        return hash_stdin_paths();
    }
    if (argc > 1 && strcmp(argv[1], "--") == 0) {
        if (argc == 2) {
            fprintf(stderr, "Usage: mvt-hash -- FILE...\n");
            return 2;
        }
        int status = 0;
        for (int i = 2; i < argc; ++i) {
            if (process_path(argv[i]) != 0) status = 1;
        }
        return status;
    }
    bool run_self_test = false;
    const char *batch_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--self-test") == 0) {
            if (argc != 2) {
                fprintf(stderr, "mvt-hash: --self-test takes no file arguments\n");
                return 2;
            }
            run_self_test = true;
        } else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
            if (argc != 2) {
                fprintf(stderr, "mvt-hash: --version takes no file arguments\n");
                return 2;
            }
            printf("mvt-hash %s (OpenSSL %s)\n", TOOLS_VERSION, OPENSSL_VERSION_TEXT);
            return 0;
        } else if (strcmp(argv[i], "--batch-file") == 0 && argc == 3) {
            batch_file = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Usage: mvt-hash [OPTION] [FILE]...\n");
            printf("Compute SHA256 checksums using OpenSSL EVP.\n\n");
            printf("  --self-test           run built-in verification suite\n");
            printf("  --files0-from - --zero  hash NUL-delimited stdin paths; emit NUL-delimited digests\n");
            printf("  --batch-file FILE     read file paths from newline-delimited FILE\n");
            printf("  -v, --version         output version information and exit\n");
            printf("  -h, --help            display this help and exit\n");
            return 0;
        } else if (argv[i][0] == '-' && strcmp(argv[i], "-") != 0) {
            fprintf(stderr, "mvt-hash: unknown or malformed option: %s\n", argv[i]);
            return 2;
        }
    }

    if (run_self_test) {
        if (self_test() == 0) {
            printf("mvt-hash: self-test OK\n");
            return 0;
        } else {
            fprintf(stderr, "mvt-hash: self-test FAILED\n");
            return 1;
        }
    }

    int errs = 0;

    if (batch_file) {
        FILE *bf = fopen(batch_file, "r");
        if (!bf) {
            fprintf(stderr, "mvt-hash: %s: %s\n", batch_file, strerror(errno));
            return 1;
        }
        char line[PATH_MAX];
        while (fgets(line, sizeof(line), bf)) {
            size_t l = strlen(line);
            while (l > 0 && (line[l - 1] == '\n' || line[l - 1] == '\r')) {
                line[--l] = '\0';
            }
            if (l == 0) continue;
            if (process_path(line) != 0) errs = 1;
        }
        fclose(bf);
        return errs;
    }

    int files_start = 1;
    if (files_start >= argc) {
        return process_path("-");
    }

    for (int i = files_start; i < argc; i++) {
        if (process_path(argv[i]) != 0) errs = 1;
    }

    return errs;
}

/* ========================================================================= */
/* ADB Device Watcher Daemon Component                                       */
/* ========================================================================= */

static void watcher_log(const char *msg) {
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);
    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm_buf);

    printf("[%s] [WATCHER] %s\n", tbuf, msg);
    fflush(stdout);

    FILE *f = fopen(WATCHER_LOG_FILE, "a");
    if (f) {
        fprintf(f, "[%s] [WATCHER] %s\n", tbuf, msg);
        fclose(f);
    }
}

static void send_toast(const char *title, const char *message, const char *urgency) {
    if (fork() == 0) {
        int null_fd = open("/dev/null", O_WRONLY);
        if (null_fd >= 0) {
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        execlp("notify-send", "notify-send", "-t", "3000", "-u", urgency, title, message, NULL);
        _exit(1);
    }
}

static void trigger_mvt(const char *serial) {
    char msg[512];
    snprintf(msg, sizeof(msg), "Device %.*s entered 'device' state. Spawning MVT autorun...", 120, serial);
    watcher_log(msg);

    pid_t pid = fork();
    if (pid == 0) {
        int null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            close(null_fd);
        }
        execl(AUTORUN_SCRIPT, AUTORUN_SCRIPT, "-s", serial, NULL);
        execlp("python3", "python3", AUTORUN_SCRIPT, "-s", serial, NULL);
        _exit(1);
    }
}

typedef struct {
    char serial[128];
    char state[32];
} device_entry_t;

static int cmd_watcher_main(int argc, char **argv) {
    if (argc >= 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        printf("Usage: adb-device-watcher [--help]\n");
        printf("Daemon monitoring ADB device connections and dispatching autorun.\n");
        return 0;
    }

    watcher_log("Starting ADB device watcher daemon...");
    device_entry_t known[64];
    size_t known_count = 0;

    while (!g_interrupted) {
        watcher_log("Connecting to adb track-devices...");

        int ret = system("adb start-server >/dev/null 2>&1");
        (void)ret;

        FILE *pipe = popen("adb track-devices 2>/dev/null", "r");
        if (!pipe) {
            watcher_log("Failed to spawn 'adb track-devices'. Retrying in 2 seconds...");
            sleep(2);
            continue;
        }

        char hex_len[5];
        while (!g_interrupted) {
            size_t r = fread(hex_len, 1, 4, pipe);
            if (r < 4) {
                watcher_log("track-devices connection closed or empty. Reconnecting...");
                break;
            }
            hex_len[4] = '\0';

            char *endp = NULL;
            long payload_len = strtol(hex_len, &endp, 16);
            if (endp == hex_len || payload_len < 0 || payload_len > 65536) {
                char warn[128];
                snprintf(warn, sizeof(warn), "Malformed packet header: %.*s", 32, hex_len);
                watcher_log(warn);
                break;
            }

            char *payload = malloc((size_t)payload_len + 1);
            if (!payload) break;

            if (payload_len > 0) {
                size_t pr = fread(payload, 1, (size_t)payload_len, pipe);
                payload[pr] = '\0';
            } else {
                payload[0] = '\0';
            }

            device_entry_t current[64];
            size_t current_count = 0;

            char *saveptr = NULL;
            char *line = strtok_r(payload, "\r\n", &saveptr);
            while (line && current_count < 64) {
                while (isspace((unsigned char)*line)) line++;
                char s[128] = {0};
                char st[32] = {0};
                if (sscanf(line, "%127s %31s", s, st) == 2) {
                    snprintf(current[current_count].serial, sizeof(current[current_count].serial), "%s", s);
                    snprintf(current[current_count].state, sizeof(current[current_count].state), "%s", st);
                    current_count++;
                }
                line = strtok_r(NULL, "\r\n", &saveptr);
            }
            free(payload);

            /* Check state transitions */
            for (size_t i = 0; i < current_count; i++) {
                const char *s = current[i].serial;
                const char *st = current[i].state;

                const char *old_st = NULL;
                for (size_t k = 0; k < known_count; k++) {
                    if (strcmp(known[k].serial, s) == 0) {
                        old_st = known[k].state;
                        break;
                    }
                }

                if (strcmp(st, "device") == 0 && (!old_st || strcmp(old_st, "device") != 0)) {
                    char msg[512];
                    snprintf(msg, sizeof(msg), "Device %.*s connected and authorized (state: device)", 120, s);
                    watcher_log(msg);
                    send_toast("Android Device Connected", msg, "normal");
                    trigger_mvt(s);
                } else if (strcmp(st, "unauthorized") == 0 && (!old_st || strcmp(old_st, "unauthorized") != 0)) {
                    char msg[512];
                    snprintf(msg, sizeof(msg), "Device %.*s is UNAUTHORIZED. Prompt pending on screen.", 120, s);
                    watcher_log(msg);
                    send_toast("Device Unauthorized", "Please unlock screen and accept USB debugging prompt.", "critical");
                } else if (strcmp(st, "offline") == 0 && (!old_st || strcmp(old_st, "offline") != 0)) {
                    char msg[512];
                    snprintf(msg, sizeof(msg), "Device %.*s went offline.", 120, s);
                    watcher_log(msg);
                }
            }

            /* Detect disconnected devices */
            for (size_t k = 0; k < known_count; k++) {
                bool found = false;
                for (size_t i = 0; i < current_count; i++) {
                    if (strcmp(current[i].serial, known[k].serial) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    char msg[512];
                    snprintf(msg, sizeof(msg), "Device %.*s disconnected.", 120, known[k].serial);
                    watcher_log(msg);
                    send_toast("Android Device Disconnected", msg, "low");
                }
            }

            known_count = current_count;
            for (size_t i = 0; i < current_count; i++) {
                known[i] = current[i];
            }
        }

        pclose(pipe);
        if (!g_interrupted) {
            sleep(2);
        }
    }

    watcher_log("Daemon stopping.");
    return 0;
}

/* ========================================================================= */
/* System Speedup Component (system_speedup)                                 */
/* ========================================================================= */

static void run_adb_cmd(const char *serial, const char *shell_cmd) {
    char cmd[1024];
    if (serial && serial[0]) {
        snprintf(cmd, sizeof(cmd), "adb -s '%s' shell %s", serial, shell_cmd);
    } else {
        snprintf(cmd, sizeof(cmd), "adb shell %s", shell_cmd);
    }
    printf("[*] Executing: %s\n", cmd);
    int res = system(cmd);
    (void)res;
}

static int cmd_speedup_main(int argc, char **argv) {
    char serial[128] = {0};
    char apps_arg[512] = {0};
    bool compile_all = false;
    bool force = false;

    static struct option long_options[] = {
        {"serial", required_argument, 0, 's'},
        {"apps", required_argument, 0, 'a'},
        {"all", no_argument, 0, 'A'},
        {"force", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "s:a:Afh", long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                snprintf(serial, sizeof(serial), "%s", optarg);
                break;
            case 'a':
                snprintf(apps_arg, sizeof(apps_arg), "%s", optarg);
                break;
            case 'A':
                compile_all = true;
                break;
            case 'f':
                force = true;
                break;
            case 'h':
            default:
                printf("Usage: system_speedup [-s SERIAL] [-a APPS] [-A] [-f]\n\n");
                printf("Android OS Latency Optimizer & AOT Precompiler\n\n");
                printf("Options:\n");
                printf("  -s, --serial SERIAL   Target ADB device serial\n");
                printf("  -a, --apps APPS       Comma-separated package names to compile (max 10)\n");
                printf("  -A, --all             Compile all installed non-system applications\n");
                printf("  -f, --force           Force compilation even if profiles are unchanged\n");
                printf("  -h, --help            Show this help message and exit\n");
                return 0;
        }
    }

    printf("=== Starting Android OS Latency Optimizations ===\n");
    run_adb_cmd(serial, "settings put global window_animation_scale 0.0");
    run_adb_cmd(serial, "settings put global transition_animation_scale 0.0");
    run_adb_cmd(serial, "settings put global animator_duration_scale 0.0");
    run_adb_cmd(serial, "device_config put activity_manager max_cached_processes 32");

    if (apps_arg[0]) {
        char *copy = strdup(apps_arg);
        char *token = strtok(copy, ",");
        while (token) {
            while (isspace((unsigned char)*token)) token++;
            if (*token) {
                char compile_cmd[256];
                snprintf(compile_cmd, sizeof(compile_cmd), "cmd package compile -m speed-profile %s %s",
                         force ? "-f" : "", token);
                run_adb_cmd(serial, compile_cmd);
            }
            token = strtok(NULL, ",");
        }
        free(copy);
    } else if (compile_all) {
        printf("[*] Compiling all packages with speed profile...\n");
        char compile_cmd[256];
        snprintf(compile_cmd, sizeof(compile_cmd), "cmd package compile -m speed-profile -a %s", force ? "-f" : "");
        run_adb_cmd(serial, compile_cmd);
    }

    printf("=== Optimization Complete ===\n");
    return 0;
}

/* ========================================================================= */
/* Main Multicall Dispatcher                                                 */
/* ========================================================================= */

int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    const char *prog = argv[0];
    const char *slash = strrchr(prog, '/');
    if (slash) prog = slash + 1;

    /* Multicall binary name matching */
    if (strcmp(prog, "mvt-hash") == 0) {
        return cmd_hash_main(argc, argv);
    }
    if (strcmp(prog, "adb-device-watcher") == 0) {
        return cmd_watcher_main(argc, argv);
    }
    if (strcmp(prog, "system_speedup") == 0 || strcmp(prog, "system-speedup") == 0) {
        return cmd_speedup_main(argc, argv);
    }

    /* Subcommand dispatch if called directly as mvt-tools */
    if (argc >= 2) {
        if (strcmp(argv[1], "hash") == 0 || strcmp(argv[1], "mvt-hash") == 0) {
            return cmd_hash_main(argc - 1, argv + 1);
        }
        if (strcmp(argv[1], "watcher") == 0 || strcmp(argv[1], "adb-device-watcher") == 0) {
            return cmd_watcher_main(argc - 1, argv + 1);
        }
        if (strcmp(argv[1], "speedup") == 0 || strcmp(argv[1], "system_speedup") == 0 || strcmp(argv[1], "system-speedup") == 0) {
            return cmd_speedup_main(argc - 1, argv + 1);
        }
    }

    /* Help / listing */
    printf("mvt-tools %s - Unified Native Android Forensics & Tooling\n", TOOLS_VERSION);
    printf("Usage: mvt-tools <command> [options...]\n\n");
    printf("Available commands:\n");
    printf("  hash, mvt-hash            Compute SHA256 hashes using OpenSSL EVP\n");
    printf("  watcher, adb-device-watcher  Monitor ADB device state changes and dispatch autorun\n");
    printf("  speedup, system_speedup   Optimize device latency and AOT precompile packages\n\n");
    printf("This binary also operates as a multicall binary when hardlinked or symlinked\n");
    printf("to 'mvt-hash', 'adb-device-watcher', or 'system_speedup'.\n");
    return 0;
}
