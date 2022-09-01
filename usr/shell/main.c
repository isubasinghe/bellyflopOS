#define INITIAL_LINE_SIZE 4096
#define DELIM " \t\r\n\a"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <aos/terminal.h>
#include <aos/aos_rpc.h>
#include <aos/macros.h>
#include <fs/fs.h>
#include <fs/dirent.h>
#include <aos/deferred.h>
#include <netutil/net_sockets.h>
#include <aos/bellyflop.h>

enum node_type {
    CommandType,
    PipeType,
};

struct command_node {
    char *cmd;
    int argc;
    char **argv;
};

struct parse_node {
    enum node_type type;
    union {
        struct command_node *cmd_node;
    } node;
};

struct parse_data {
    size_t pos;
    size_t length;
    char *buf;
};

static void free_cmd_node(struct command_node *cmd_node)
{
    free(cmd_node->cmd);
    for (int i = 0; i < cmd_node->argc; i++) {
        free(cmd_node->argv[i]);
    }
    free(cmd_node->argv);
    free(cmd_node);
}

static void free_parse_node(struct parse_node *node)
{
    switch (node->type) {
    case CommandType:
        free_cmd_node(node->node.cmd_node);
        break;
    case PipeType:
        break;
    }
}

static char pd_getchar(struct parse_data *data)
{
    if (data->pos >= data->length) {
        return 0;
    }

    char c = data->buf[data->pos];
    data->pos = data->pos + 1;
    return c;
}

static inline char pd_lookahead(struct parse_data *data)
{
    if (data->pos >= data->length) {
        return 0;
    }
    char c = data->buf[data->pos];
    return c;
}

static void parse_whitespace(struct parse_data *data)
{
    while (1) {
        char c = pd_lookahead(data);
        switch (c) {
        case ' ':
        case '\t':
            pd_getchar(data);
            break;
        default:
            return;
        }
    }
}

static char *parse_string(struct parse_data *data)
{
    char *start = &data->buf[data->pos];
    size_t curr_pos = data->pos;

    while (curr_pos < data->length) {
        char c = data->buf[curr_pos];
        if (c == '\t' || c == ' ' || c == '\n') {
            break;
        }
        curr_pos++;
    }

    if (!(curr_pos > data->pos)) {
        return NULL;
    }

    size_t sz = curr_pos - data->pos + 1;  // 0
    data->pos = curr_pos;
    char *buffer = malloc(sizeof(char) * sz);
    memset(buffer, 0, sz);
    memcpy(buffer, start, sz - 1);
    return buffer;
}

static struct parse_node *parse_command(struct parse_data *data)
{
    parse_whitespace(data);
    struct command_node *cmd_node = malloc(sizeof(struct command_node));
    char *cmd = parse_string(data);

    if (cmd == NULL) {
        return NULL;
    }

    cmd_node->cmd = cmd;

    int cap = 2;
    int written = 0;
    cmd_node->argv = malloc(sizeof(char *) * 2);

    while (1) {
        parse_whitespace(data);
        char *str = parse_string(data);
        if (str == NULL) {
            break;
        }

        if (written + 2 > cap) {
            cmd_node->argv = realloc(cmd_node->argv, sizeof(char **) * cap * 2);
            cap = cap * 2;
        }
        cmd_node->argv[written] = str;
        written += 1;
    }

    cmd_node->argc = written;

    struct parse_node *node = malloc(sizeof(struct parse_node));
    node->node.cmd_node = cmd_node;
    node->type = CommandType;

    return node;
}

__unused static struct parse_node *parse_node(struct parse_data *data)
{
    parse_whitespace(data);
    char c = pd_lookahead(data);
    switch (c) {
    case '<':
    case '>':
        return NULL;
    case 0:
        return NULL;
    default:
        return parse_command(data);
    }
}

struct aos_terminal *term = NULL;

static void ps(int argc, char **argv)
{
    printf("[CoreId]\t[DomainId]\n");
    domainid_t *pids;
    size_t n_pids = 0;
    errval_t err = aos_rpc_process_get_all_pids(get_init_rpc(), &pids, &n_pids);
    if (err_is_fail(err)) {
        printf("ERROR COULD NOT MAKE RPC: ERRCODE %lu\n", err);
        return;
    }

    for (size_t i = 0; i < n_pids; i++) {
        printf("%7d\t%17u\n", did_get_coreid(pids[i]), pids[i]);
    }
    free(pids);
}

static void pname(int argc, char **argv)
{
    if (argc != 1) {
        printf("Usage: pname <pid>\n");
        return;
    }

    domainid_t pid;
    if (sscanf(argv[0], "%u", &pid) != 1) {
        printf("Failed to read pid\n");
    }

    char *name;
    errval_t err = aos_rpc_process_get_name(get_init_rpc(), pid, &name);
    if (err_is_fail(err)) {
        printf("Got error code %lu\n", err);
        return;
    }
    printf("pid %u has name <%s>\n", pid, name);

    free(name);
}

static void echo(int argc, char **argv)
{
    if (argc == 0) {
        return;
    }
    for (int i = 0; i < argc; i++) {
        printf("%s", argv[i]);
        if (i == argc - 1) {
            printf("\n");
        } else {
            printf(" ");
        }
    }
}

static char *join(char **strs, int nstrs, int from, int to, char sep)
{
    size_t tot_size = 0;
    int *sizes = malloc(sizeof(int) * nstrs);

    for (int i = from; i < to; i++) {
        int ilen = strlen(strs[i]);
        tot_size += ilen + 2;  // +1 for sep
        sizes[i] = ilen;
    }

    char *buffer = malloc(sizeof(char) * tot_size);
    memset(buffer, 0, tot_size);
    char *buffer_start = buffer;

    for (int i = from; i < to; i++) {
        memcpy(buffer, strs[i], sizes[i]);
        buffer[sizes[i]] = sep;
        if (i == to - 1) {
            buffer[sizes[i]] = '\0';
        }
        buffer += sizes[i] + 1;
    }
    free(sizes);
    return buffer_start;
}

static void oncore(int argc, char **argv, bool give_away_terminal)
{
    if (argc < 2) {
        printf("Usage: oncore <coreid> <binaryname>\r\n");
        return;
    }

    if (argv[0][0] < '0' || argv[0][0] >= '4') {
        printf("Invalid coreid\r\n");
        return;
    }

    domainid_t pid;
    int coreid = atoi(argv[0]);
    char *cmdline = join(argv, argc, 1, argc, ' ');

    if (give_away_terminal) {
        aos_terminal_release(term);
    }

    errval_t err = aos_rpc_process_spawn(get_init_rpc(), cmdline, coreid, &pid);
    if (err_is_fail(err)) {
        printf("Was unable to spawn process\n");
        free(cmdline);
        return;
    }


    printf("Spawned process %s on core %d with pid %d\n", argv[1], coreid, pid);

    if (give_away_terminal) {
        barrelfish_usleep(1000 * 1000 * 5);

        while (!aos_terminal_lock(term)) {
            // sleep for 500ms
            barrelfish_usleep(1000 * 500);
        }
    }
    free(cmdline);
}

static errval_t run_command(char *cmdline)
{
    domainid_t pid;
    errval_t err = aos_rpc_process_spawn(get_init_rpc(), cmdline, 3, &pid);
    RETURN_IF_ERR(err);


    volatile int cnt = 0;
    while (cnt == 10) {
        cnt++;
        thread_yield();
    }

    printf("Spawned process %s on core %d with pid %d\n", cmdline, 3, pid);
    return SYS_ERR_OK;
}

static void help(void)
{
    printf("Available commands: {help,ls,cat,mkdir,rmdir,oncore, "
           "ps, echo}\n");
}

static void ls(int argc, char **argv)
{
    if (argc < 1) {
        printf("Usage: ls <path> \n");
        return;
    }
    fs_dirhandle_t handle;
    errval_t err = opendir(argv[0], &handle);
    if (err_is_fail(err)) {
        DEBUG_ERR(err, "opendir\n");
        printf("Could not open directory %s\n", argv[0]);
        return;
    }

    while (true) {
        char *name;
        err = readdir(handle, &name);
        printf("%s/%s", argv[0], name);
        if (err_is_ok(err)) {
            break;
        }
        free(name);
    }

    if (err_no(err) != FS_ERR_INVALID_FH) {
        DEBUG_ERR(err, "readdir failed\n");
    }

    closedir(handle);
}


__unused static void cat(int argc, char **argv)
{
    if (argc != 1) {
        printf("Usage: cat <filename>\n");
        return;
    }
    FILE *fp = fopen(argv[0], "r");
    if (fp == NULL) {
        printf("Unable to open %s\n", argv[0]);
        return;
    }

    char *buffer = malloc(sizeof(char) * 1024);
    buffer[0] = 0;
    buffer[1] = 0;

    size_t cap = 1024;
    size_t written = 0;

    signed char c;
    while ((c = fgetc(fp)) != EOF) {
        if (written + 4 > cap) {
            buffer = realloc(buffer, sizeof(char) * cap * 2);
            cap = cap * 2;
        }
        buffer[written] = c;
        written++;
    }

    buffer[written] = 0;
    fclose(fp);
    printf("%s\n", buffer);
    free(buffer);
}

static void append_to_file(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: append_to_file <filename> <string>\n");
        return;
    }
    char *name = argv[0];
    FILE *fp = fopen(name, "a");

    if (fp == NULL) {
        printf("Unable to open %s\n", name);
        return;
    }

    char *s = join(argv, argc, 1, argc, ' ');
    size_t len = strlen(s);

    size_t ret = fwrite(s, 1, len, fp);
    if (ret != len) {
        DEBUG_PRINTF("only wrote %d characters\n", ret);
    }

    fclose(fp);
    free(s);
}

static void echo_to_file(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: echo_to_file <filename> <string>\n");
        return;
    }
    char *name = argv[0];
    FILE *fp = fopen(name, "w");

    if (fp == NULL) {
        printf("Unable to open %s\n", name);
        return;
    }

    char *s = join(argv, argc, 1, argc, ' ');
    size_t len = strlen(s);

    size_t ret = fwrite(s, 1, len, fp);
    if (ret != len) {
        DEBUG_PRINTF("only wrote %d characters\n", ret);
    }

    fclose(fp);
    free(s);
}

static void cmd_rm(int argc, char **argv)
{
    if (argc < 1) {
        printf("Usage: rm <path> \n");
        return;
    }
    char *name = argv[0];

    errval_t err = rm(name);
    if (err_is_fail(err)) {
        printf("rm %s failed\n", name);
        return;
    }
}

static void touch(int argc, char **argv)
{
    if (argc < 1) {
        printf("Usage: touch <path> \n");
        return;
    }
    char *name = argv[0];
    FILE *fp = fopen(name, "r");
    if (fp != NULL) {
        printf("File %s exists\n", name);
        fclose(fp);
        return;
    }

    fp = fopen(name, "w");
    if (fp == NULL) {
        printf("Couldn't open file, because reasons...\n");
        return;
    }
    fclose(fp);
}

__unused static void cmd_mkdir(int argc, char **argv)
{
    if (argc != 1 && argc != 2) {
        printf("Usage: mkdir <path>\n");
        return;
    }
    errval_t err = mkdir(argv[0]);
    DEBUG_IF_ERR(err, "mkdir failed\n");
}

__unused static void cmd_rmdir(int argc, char **argv)
{
    if (argc != 1 && argc != 2) {
        printf("Usage: rmdir <path>\n");
        return;
    }
    errval_t err = rmdir(argv[0]);
    DEBUG_IF_ERR(err, "rmdir failed\n");
}

// arp 10.0.2.2
static void arp_request(int argc, char **argv)
{
    if (!(argc == 2 || argc == 3)) {
        printf("Usage: arp_request <ip> <timeout>\n");
        return;
    }
    ip_addr_t ip = str_to_ip_addr(argv[0]);
    size_t timeout = 1000 * 1000;
    if (argc == 2) {
        if (sscanf(argv[1], "%zu", &timeout) != 1) {
            printf("Failed to read timeout\n");
            return;
        }
        timeout = atoi(argv[1]) * 1000;
    }
    if (ip == 0) {
        printf("Invalid IP address\n");
        return;
    }
    errval_t err = net_socket_arp_request(ip, timeout);
    if (err_is_fail(err)) {
        printf("ARP request timed out\n");
        return;
    }
    printf("ARP request successful.\n");
}

static void pretty_print_services(ServiceInfo **services, size_t num)
{
    printf("#  Name                SID\n");
    for (size_t i = 0; i < num; ++i) {
        char sid_str[64];
        sid_to_str(services[i]->sid, sid_str);
        printf("%*d%*s%s\n", -3, i + 1, -20, services[i]->name, sid_str);
    }
}

static void nslist(int argc, char **argv)
{
    if (argc > 0) {
        printf("Usage: nslist\n");
        return;
    }

    size_t num = 0;
    ServiceInfo **services;
    errval_t err = nameservice_enumerate_services("", &num, &services);
    if (err_is_fail(err)) {
        printf("nameservice_enumerate() failed\n");
        return;
    }

    pretty_print_services(services, num);
    free_service_info_arr(services, num);
}

static void nslookup(int argc, char **argv)
{
    if (argc != 1) {
        printf("Usage: nslookup <name>\n");
        return;
    }

    size_t num = 0;
    ServiceInfo **services;
    errval_t err = nameservice_enumerate_services(argv[0], &num, &services);
    if (err_is_fail(err)) {
        printf("nameservice_enumerate_services() failed\n");
        return;
    }

    pretty_print_services(services, num);
    free_service_info_arr(services, num);
}

static void repl_loop(void)
{
    int quit = 0;
    while (!quit) {
        printf("$> ");
        size_t length = 0;
        char *data = aos_terminal_readline(term);
        while (data == NULL) {
            data = aos_terminal_readline(term);
        }
        length = strlen(data);
        struct parse_data pdata = { .pos = 0, .length = length, .buf = data };

        struct parse_node *n = parse_command(&pdata);
        if (n == NULL) {
            // error
            continue;
        }
        if (strcmp("echo", n->node.cmd_node->cmd) == 0) {
            echo(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("help", n->node.cmd_node->cmd) == 0) {
            help();
        } else if (strcmp("ls", n->node.cmd_node->cmd) == 0) {
            ls(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("oncore", n->node.cmd_node->cmd) == 0) {
            oncore(n->node.cmd_node->argc, n->node.cmd_node->argv, false);
        } else if (strcmp("run", n->node.cmd_node->cmd) == 0) {
            oncore(n->node.cmd_node->argc, n->node.cmd_node->argv, true);
        } else if (strcmp("cat", n->node.cmd_node->cmd) == 0) {
            cat(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("mkdir", n->node.cmd_node->cmd) == 0) {
            cmd_mkdir(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("touch", n->node.cmd_node->cmd) == 0) {
            touch(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("rm", n->node.cmd_node->cmd) == 0) {
            cmd_rm(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("rmdir", n->node.cmd_node->cmd) == 0) {
            cmd_rmdir(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("echo_to_file", n->node.cmd_node->cmd) == 0) {
            echo_to_file(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("append_to_file", n->node.cmd_node->cmd) == 0) {
            append_to_file(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("ps", n->node.cmd_node->cmd) == 0) {
            ps(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("term_debug", n->node.cmd_node->cmd) == 0) {
            aos_terminal_debug(term);
        } else if (strcmp("pname", n->node.cmd_node->cmd) == 0) {
            pname(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("arptable", n->node.cmd_node->cmd) == 0) {
            net_sockets_print_arp_table();
        } else if (strcmp("arp", n->node.cmd_node->cmd) == 0) {
            arp_request(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("bellyflop", n->node.cmd_node->cmd) == 0) {
            printf(belly_flop_get_small());
        } else if (strcmp("nslist", n->node.cmd_node->cmd) == 0) {
            nslist(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else if (strcmp("nslookup", n->node.cmd_node->cmd) == 0) {
            nslookup(n->node.cmd_node->argc, n->node.cmd_node->argv);
        } else {
            errval_t err = run_command(data);
            if (err_is_fail(err)) {
                printf("UNKNOWN COMMAND\n");
            }
        }

        free_parse_node(n);
        free(data);
    }
}


static const char *welcome_banner = "_________________________________________________\n"
                                    "|   __   ___                ___       __   __   |\n"
                                    "|  |__) |__  |    |    \\ / |__  |    /  \\ |__)  |\n"
                                    "|  |__) |___ |___ |___  |  |    |___ \\__/ |     |\n"
                                    "|                                               |\n"
                                    "|             __        ___                     |\n"
                                    "|            /__` |__| |__  |    |              |\n"
                                    "|            .__/ |  | |___ |___ |___           |\n"
                                    "|                                               |\n"
                                    "|_______________________________________________|\n"
                                    "\n";


int main(int argc, char *argv[])
{
    // printf("STARTED SHELL ON DOMAIN %u\n", disp_get_domain_id());
    //  Lets print the Welcome string.
    printf(welcome_banner);
    term = get_default_terminal();
    while (!aos_terminal_lock(term)) {
    }
    setbuf(stdout, NULL);

    errval_t err = filesystem_init();
    if (err_is_fail(err)) {
        printf("FAILED SETTING UP FILESYSTEM... exiting\n");
        return -1;
    }

    repl_loop();
}
