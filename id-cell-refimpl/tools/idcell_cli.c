/*
 * ID-CELL 主机侧命令行工具（idcell-cli）
 * ============================================================================
 *
 * 这是「主机侧执行入口」。设备侧入口是 idcell_node_poll()；
 * 主机侧则由本工具承担：扫描设备、按名选设备、发需求、看数据、发起写。
 *
 * 一条硬约束贯穿整个 CLI：**命令行里不出现 DID。**
 *
 *   需求描述与设备身份是解耦的（FR-011）——
 *   「我要一个能提供加速度的设备」写在需求里，
 *   「那是哪一台设备」由发现过程给出。
 *   用户只需要用可读名指认设备（--device IMU-6DOF），
 *   不需要抄一串十六进制身份。
 *
 * 五个子命令：
 *   scan       扫描链路，列出可见设备（可读名 + 能力点数 + 管道阶段）
 *   match      发一条需求，跑完管道，打印绑定契约
 *   bind       与指定可读名的设备完成绑定并打印契约
 *   monitor    绑定后持续打印实时数据流
 *   write      绑定后发起一次写，异步打印裁决结果
 *
 * 链路：默认串口（--port COM3 / --port /dev/ttyUSB0）。
 *       另提供 --loopback 模式：本进程内挂一个仿真设备，
 *       用来在没有硬件时验证 CLI 自身的行为。
 *
 * 编译：
 *     python -m ziglang cc -std=c99 -Iinclude -o idcell-cli.exe \
 *         tools\idcell_cli.c src\*.c
 * ============================================================================
 */
#include "idcell.h"
#include "idcell_transport.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <shellapi.h>
#else
#  include <time.h>
#endif

#ifdef _WIN32
/*
 * Windows 的 CRT 用 ACP（中文系统为 GBK/936）把宽命令行转成 argv，
 * 于是 --intent "温漂补偿" 这类中文参数会变成乱码字节——
 * 终端里是乱码，发到链路上的也是乱码。
 *
 * 这里绕开 CRT 的转换：直接取原始 UTF-16 命令行，统一转成 UTF-8。
 * 意图串要跨设备送达（SEC-019），字节编码必须确定，不能随系统区域设置变。
 */
static int cli_utf8_argv(int *argc_out, char ***argv_out)
{
    int n = 0, i;
    LPWSTR *wargv;
    char **v;

    wargv = CommandLineToArgvW(GetCommandLineW(), &n);
    if (!wargv) return -1;

    v = (char **)calloc((size_t)n + 1, sizeof(char *));
    if (!v) { LocalFree(wargv); return -1; }

    for (i = 0; i < n; i++) {
        int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);
        if (len <= 0) { v[i] = NULL; continue; }
        v[i] = (char *)malloc((size_t)len);
        if (!v[i]) { LocalFree(wargv); return -1; }
        WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, v[i], len, NULL, NULL);
    }
    LocalFree(wargv);

    *argc_out = n;
    *argv_out = v;
    return 0;
}
#endif

/* ---------------------------------------------------------------- 参数 */

typedef struct {
    const char *cmd;
    const char *port;         /* 串口设备名 */
    uint32_t    baud;
    int         loopback;     /* 内置仿真设备 */
    const char *device;       /* 目标设备可读名 */
    const char *qty;          /* 需求的量种名（如 acceleration） */
    const char *unit;         /* 需求的单位（UCUM 码） */
    uint32_t    want_ms;      /* T_want */
    uint32_t    stale_ms;     /* T_stale */
    uint16_t    index;        /* 写操作的目标能力点 */
    uint8_t     sub;
    double      value;
    const char *intent;       /* 写意图（SEC-019 强制） */
    uint32_t    duration_ms;  /* monitor 时长 */
    uint32_t    timeout_ms;   /* 管道超时 */
} cli_args_t;

static void usage(void)
{
    printf(
"ID-CELL 主机侧命令行工具\n"
"\n"
"用法：idcell-cli <子命令> [选项]\n"
"\n"
"子命令：\n"
"  scan                扫描链路，列出可见设备\n"
"  match               发一条需求并跑完管道，打印绑定契约\n"
"  bind                与指定可读名的设备完成绑定并打印契约\n"
"  monitor             绑定后持续打印实时数据流\n"
"  write               绑定后发起一次写，异步打印裁决\n"
"\n"
"通用选项：\n"
"  --port <串口>       串口设备（COM3 / /dev/ttyUSB0）\n"
"  --baud <n>          波特率，默认 115200\n"
"  --loopback          内置仿真设备（无需硬件，用于验证 CLI 自身）\n"
"  --device <可读名>   目标设备（按名选设备，不使用 DID）\n"
"  --timeout <ms>      管道超时，默认 8000\n"
"\n"
"需求选项（match / bind / monitor / write）：\n"
"  --qty <量种名>      需求的量种，如 acceleration / force / temperature\n"
"  --unit <单位>       需求的单位（UCUM 规范码），如 m/s2 / N / Cel\n"
"  --want-ms <n>       期望同步周期 T_want，默认 20\n"
"  --stale-ms <n>      保鲜上限 T_stale，默认 500\n"
"\n"
"写选项（write）：\n"
"  --index <n>         目标能力点索引（十进制或 0x 十六进制）\n"
"  --sub <n>           目标能力点的子索引，默认 0\n"
"  --value <n>         写入值\n"
"  --intent <文本>     写意图串（必填，缺则写被拒）\n"
"\n"
"monitor 选项：\n"
"  --duration <ms>     监控时长，默认 5000\n"
"\n"
"示例：\n"
"  idcell-cli scan --port COM3\n"
"  idcell-cli match --port COM3 --qty acceleration --unit m/s2\n"
"  idcell-cli monitor --port COM3 --device IMU-6DOF --qty acceleration --unit m/s2\n"
"  idcell-cli write --port COM3 --device IMU-6DOF --qty temperature --unit Cel \\\n"
"                   --index 0x0200 --value 26.5 --intent \"温漂补偿\"\n");
}

/* ---------------------------------------------------------------- 仿真设备 */

/*
 * --loopback 模式下的仿真提供方：一个小 IMU。
 * 它让 CLI 在没有硬件时也能被完整验证——
 * 否则 CLI 的行为只能靠「用户手边正好有设备」来保证。
 */
typedef struct {
    double accel;
    double temp;
    uint64_t tick;
} sim_dev_t;

static int sim_read(void *ud, uint16_t index, uint8_t sub,
                    double *value, uint64_t *ts_us, idcell_prov_t *prov)
{
    sim_dev_t *d = (sim_dev_t *)ud;
    (void)sub;
    switch (index) {
    case 0x0100: *value = d->accel; break;
    case 0x0200: *value = d->temp;  break;
    default: return IDCELL_E_NODEV;
    }
    *ts_us = d->tick * 5000;
    *prov = IDCELL_PROV_MEASURED;
    return IDCELL_OK;
}

static int sim_write(void *ud, uint16_t index, uint8_t sub,
                     double value, const char *intent, uint32_t owner_token)
{
    sim_dev_t *d = (sim_dev_t *)ud;
    (void)sub; (void)owner_token;
    printf("    [仿真设备] 收到写 index=0x%04X value=%.3f intent=\"%s\"\n",
           index, value, intent ? intent : "");
    if (index == 0x0200) d->temp = value;
    return IDCELL_OK;
}

static void fill_sim_cap(idcell_capability_t *c, uint16_t index, const char *label,
                          idcell_qty_t qty, const char *unit,
                          double lo, double hi, uint32_t min_sync, uint32_t stale)
{
    memset(c, 0, sizeof(*c));
    c->index = index;
    c->label[0] = '\0';
    snprintf(c->label, sizeof(c->label), "%s", label);
    c->kind = IDCELL_KIND_STATE;
    c->dir = IDCELL_DIR_R;
    c->perm = IDCELL_PERM_P1;
    c->qty = qty;                          /* v0.8：量种 ID */
    snprintf(c->unit, sizeof(c->unit), "%s", unit);   /* UCUM 码 */
    c->accept_count = 1;
    snprintf(c->accept_units[0], sizeof(c->accept_units[0]), "%s", unit);
    c->conv_class = IDCELL_CONV_T1;
    c->dtype = IDCELL_DTYPE_F64;           /* v0.8 */
    c->scale_exp = 0;                      /* v0.8 */
    /* v0.9：可接受值类型（§24.8） */
    idcell_type_list_add(c->accept_types, &c->accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(c->accept_types, &c->accept_type_count, IDCELL_DTYPE_I32, 3);
    c->range[0] = lo;
    c->range[1] = hi;
    c->precision = 0.001;
    c->min_sync_ms = min_sync;
    c->stale_ms = stale;
    c->fail_action = IDCELL_FAIL_HOLD;
    c->provenance = IDCELL_PROV_MEASURED;
}

/* ---------------------------------------------------------------- 回调 */

static void cli_on_data(void *ud, const idcell_did_t *peer,
                        uint16_t index, uint8_t sub, double value,
                        uint64_t ts_us, idcell_prov_t prov,
                        idcell_quality_t quality)
{
    static const char *prov_name[] = { "measured", "estimated", "derived", "sampled" };
    static const char *qual_name[] = { "good", "uncertain", "bad" };
    (void)ud; (void)peer; (void)sub;
    printf("    index=0x%04X  value=%.4f  ts=%lluus  来源=%s  质量=%s\n",
           index, value, (unsigned long long)ts_us,
           (prov < 4) ? prov_name[prov] : "unknown",
           (quality < 3) ? qual_name[quality] : "unknown");
}

static void cli_on_write_result(void *ud, const idcell_did_t *peer,
                                uint16_t index, uint8_t sub,
                                const idcell_write_result_t *res)
{
    (void)ud; (void)peer; (void)sub;
    printf("    裁决 index=0x%04X -> %s", index, idcell_err_name((idcell_err_t)res->err));
    if (res->has_range)
        printf("（值 %.3f 超出值域 [%.3f, %.3f]）", res->value, res->range_lo, res->range_hi);
    else if (res->reason)
        printf("（%s）", res->reason);
    printf("\n");
}

/* ---------------------------------------------------------------- 工具 */

static uint32_t now_ms(void)
{
    /* 单调毫秒。用时钟而非墙钟：墙钟跳变会让租约与周期全乱。 */
#ifdef _WIN32
    return (uint32_t)(GetTickCount64());
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000ULL + ts.tv_nsec / 1000000ULL);
#endif
}

static void sleep_ms(uint32_t ms)
{
#ifdef _WIN32
    Sleep(ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

static int parse_u32(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long v;
    if (!s || !*s) return 0;
    v = strtoul(s, &end, 0);   /* 0 = 自动识别 0x 前缀 */
    if (!end || *end) return 0;
    *out = (uint32_t)v;
    return 1;
}

static int parse_double(const char *s, double *out)
{
    char *end = NULL;
    double v;
    if (!s || !*s) return 0;
    v = strtod(s, &end);
    if (!end || *end) return 0;
    *out = v;
    return 1;
}

/* ---------------------------------------------------------------- 节点装配 */

typedef struct {
    idcell_node_t    *host;      /* 主机侧节点（需求方） */
    idcell_node_t    *sim;       /* 仿真设备节点（仅 loopback 模式） */
    idcell_loopback_t *lb;
    idcell_transport_t tr;
    void             *serial;
    sim_dev_t         sim_state;
} cli_ctx_t;

static void cli_ctx_free(cli_ctx_t *c)
{
    if (c->host) idcell_node_free(c->host);
    if (c->sim) idcell_node_free(c->sim);
    if (c->lb) idcell_loopback_free(c->lb);
    if (c->serial) idcell_serial_close(&c->tr);
    memset(c, 0, sizeof(*c));
}

/*
 * 建主机侧节点。
 * 主机侧也是需求方：它注册需求，走同一套六段管道。
 */
static int cli_setup(cli_ctx_t *c, const cli_args_t *a)
{
    idcell_node_cfg_t cfg;
    idcell_capability_t cap;
    idcell_requirement_t req;

    memset(c, 0, sizeof(*c));

    if (a->loopback) {
        idcell_transport_t tr_sim;
        c->lb = idcell_loopback_new();
        if (!c->lb) return IDCELL_E_NODEV;
        idcell_loopback_endpoints(c->lb, &c->tr, &tr_sim);

        /* 仿真设备：提供方 */
        memset(&cfg, 0, sizeof(cfg));
        idcell_did_generate(0x51DE0001, &cfg.did);
        memset(cfg.cred, 0x5A, sizeof(cfg.cred));
        cfg.max_perm = IDCELL_PERM_P2;
        cfg.proficiency = 2;
        cfg.t_hb_ms = 1000;
        cfg.lease_ttl_ms = 3000;
        cfg.announce_ms = 200;
        snprintf(cfg.vendor, sizeof(cfg.vendor), "SimVendor");
        snprintf(cfg.model, sizeof(cfg.model), "IMU-6DOF");

        c->sim = idcell_node_new(&cfg);
        if (!c->sim) return IDCELL_E_NODEV;
        idcell_node_set_transport(c->sim, &tr_sim);

        fill_sim_cap(&cap, 0x0100, "imu.accel.x", IDCELL_QTY_ACCELERATION, "m/s2",
                     -160.0, 160.0, 20, 500);
        idcell_node_register_capability(c->sim, &cap);
        fill_sim_cap(&cap, 0x0200, "imu.temperature", IDCELL_QTY_TEMPERATURE, "Cel",
                     -40.0, 85.0, 200, 2000);
        cap.dir = IDCELL_DIR_RW;
        cap.perm = IDCELL_PERM_P2;
        idcell_node_register_capability(c->sim, &cap);

        c->sim_state.accel = 0.12;
        c->sim_state.temp = 27.5;
        c->sim_state.tick = 1;
        idcell_node_set_value_source(c->sim, sim_read, &c->sim_state);
        idcell_node_set_setter(c->sim, sim_write, &c->sim_state);
    } else {
        if (!a->port) {
            fprintf(stderr, "错误：需要 --port <串口>，或用 --loopback 走内置仿真。\n");
            return IDCELL_E_NODEV;
        }
        if (idcell_serial_open(a->port, a->baud, &c->tr, &c->serial) != IDCELL_OK) {
            fprintf(stderr, "错误：打不开串口 %s。\n", a->port);
            return IDCELL_E_UNSAFE;
        }
    }

    /* 主机侧节点 */
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0xA11CE000, &cfg.did);
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.proficiency = 2;
    cfg.t_hb_ms = 1000;
    cfg.lease_ttl_ms = 3000;
    cfg.announce_ms = 200;
    snprintf(cfg.vendor, sizeof(cfg.vendor), "Host");
    snprintf(cfg.model, sizeof(cfg.model), "CLI");

    c->host = idcell_node_new(&cfg);
    if (!c->host) return IDCELL_E_NODEV;
    idcell_node_set_transport(c->host, &c->tr);
    idcell_node_set_data_sink(c->host, cli_on_data, NULL);
    idcell_node_set_write_result_sink(c->host, cli_on_write_result, NULL);

    /*
     * 链路画像：从适配器取。物理链路类型由此可知——
     * CLI 启动时会把它打印出来，用户能立刻知道自己在哪条链路上。
     */
    {
        const idcell_link_profile_t *lp = idcell_node_link_profile(c->host);
        if (lp) {
            printf("链路：介质=%s 拓扑=%s T_link_min=%ums MTU=%u 主机代发=%s\n",
                   idcell_media_name(lp->media), idcell_topology_name(lp->topology),
                   lp->t_link_min_ms, lp->mtu, lp->host_proxy ? "是" : "否");
        }
    }

    /* 需求：只说「我要什么」，不含设备身份（FR-011） */
    if (a->qty && a->unit) {
        idcell_qty_t q;
        if (idcell_qty_by_name(a->qty, &q) != IDCELL_OK) {
            fprintf(stderr, "错误：未知量种「%s」。可用量种：", a->qty);
            {
                int k;
                for (k = 0; k < IDCELL_QTY_COUNT; k++)
                    fprintf(stderr, "%s ", idcell_qty_name((idcell_qty_t)k));
            }
            fprintf(stderr, "\n");
            return IDCELL_E_NODEV;
        }
        memset(&req, 0, sizeof(req));
        snprintf(req.label, sizeof(req.label), "CLI 需求");
        req.qty = q;                          /* v0.8：量种 ID */
        snprintf(req.unit, sizeof(req.unit), "%s", a->unit);   /* UCUM 码 */
        req.accept_count = 1;
        snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "%s", a->unit);
        /* v0.9：需求方可接受值类型（§24.8） */
        idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
        idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_I32, 3);
        req.perm = IDCELL_PERM_P2;
        req.index = 0xFFFF;
        req.want_ms = a->want_ms;
        req.stale_ms = a->stale_ms;
        req.kind = IDCELL_KIND_STATE;
        idcell_node_register_requirement(c->host, &req);
    }

    /* 按名选设备：命令行里只有可读名，没有 DID */
    if (a->device) idcell_node_set_target_label(c->host, a->device);

    return IDCELL_OK;
}

/* 推进一轮：主机侧与仿真设备都 poll */
static void cli_poll(cli_ctx_t *c, uint32_t now)
{
    /*
     * 仿真设备按 200 Hz 推进：值真的变了才发。
     * 这正是「值未更新就不发、绝不重复旧值伪装刷新」这条红线在真机上的样子——
     * 如果把 tick 固定住，monitor 会一直只收到第一条数据。
     */
    if (c->sim) {
        c->sim_state.tick++;
        c->sim_state.accel = 0.12 + 0.4 * sin((double)now / 400.0);
    }
    idcell_node_poll(c->host, now);
    if (c->sim) idcell_node_poll(c->sim, now);
}

/* ---------------------------------------------------------------- 子命令 */

/* scan：只扫描，不发需求 */
static int cmd_scan(cli_ctx_t *c, const cli_args_t *a)
{
    uint32_t start = now_ms();
    uint32_t deadline;
    int count = 0;

    (void)a;

    printf("扫描中（3 秒）…\n");
    deadline = start + 3000;
    while (now_ms() < deadline) {
        cli_poll(c, now_ms());
        sleep_ms(20);
    }

    count = idcell_node_peer_count(c->host);
    if (count == 0) {
        printf("链路上没有发现任何设备。\n");
        return 1;
    }

    printf("发现 %d 台设备：\n", count);
    {
        int i;
        for (i = 0; i < count; i++) {
            idcell_did_t did;
            char label[IDCELL_MAX_LABEL];
            if (idcell_node_peer(c->host, i, &did) != IDCELL_OK) continue;
            if (idcell_node_peer_label(c->host, &did, label, sizeof(label)) != IDCELL_OK)
                continue;
            printf("  %-24s 能力点 %2d 个  阶段 %s\n",
                   label,
                   idcell_node_peer_cap_count(c->host, &did),
                   idcell_node_peer_stage_name(c->host, &did));
        }
    }
    return 0;
}

/* 跑管道直到某对端进入 RUNNING（或超时） */
static int wait_bound(cli_ctx_t *c, const cli_args_t *a, idcell_did_t *out)
{
    uint32_t deadline = now_ms() + a->timeout_ms;

    while (now_ms() < deadline) {
        uint32_t now = now_ms();
        int i, count = idcell_node_peer_count(c->host);

        cli_poll(c, now);

        for (i = 0; i < count; i++) {
            idcell_did_t did;
            idcell_contract_t ct;
            if (idcell_node_peer(c->host, i, &did) != IDCELL_OK) continue;
            if (idcell_node_get_contract(c->host, &did, &ct) != IDCELL_OK) continue;
            *out = did;
            return IDCELL_OK;
        }
        sleep_ms(20);
    }
    return IDCELL_E_LEASE;
}

/* 打印契约十字段 */
static void print_contract(const idcell_contract_t *ct)
{
    uint16_t i;
    printf("绑定契约（§09.7）：\n");
    printf("  binding_id  = 0x%08X\n", ct->binding_id);
    printf("  cap_list    = %u 个能力点\n", ct->pt_count);
    for (i = 0; i < ct->pt_count; i++) {
        printf("      index=0x%04X sub=%u unit=%-8s T_pub=%-5ums P%u 降级=%s\n",
               ct->pt[i].index, ct->pt[i].sub, ct->pt[i].unit,
               ct->pt[i].t_pub_ms, (unsigned)ct->pt[i].perm,
               ct->pt[i].degrade == IDCELL_FAIL_HOLD ? "hold" :
               ct->pt[i].degrade == IDCELL_FAIL_BRAKE ? "brake" :
               ct->pt[i].degrade == IDCELL_FAIL_DAMP ? "damp" : "off");
    }
    printf("  arb_domain  = 0x%08X\n", ct->arb_domain);
    printf("  lease_ttl   = %ums\n", ct->lease_ttl_ms);
    /* SEC-067：完整 owner_token MUST NOT 出现在输出里，只给不可直接复用的短前缀 */
    {
        char masked[24];
        idcell_mask_token(ct->owner_token, masked, sizeof(masked));
        printf("  owner_token = %s\n", masked);
    }
    printf("  desc_version= %u\n", ct->desc_version);
}

/* match / bind：跑完管道并打印契约 */
static int cmd_bind(cli_ctx_t *c, const cli_args_t *a)
{
    idcell_did_t did;
    idcell_contract_t ct;
    char label[IDCELL_MAX_LABEL];
    int rc = wait_bound(c, a, &did);

    if (rc != IDCELL_OK) {
        printf("管道未在 %ums 内完成绑定。\n", a->timeout_ms);
        printf("链路上可见的对端：\n");
        {
            int i, count = idcell_node_peer_count(c->host);
            for (i = 0; i < count; i++) {
                idcell_did_t d;
                if (idcell_node_peer(c->host, i, &d) != IDCELL_OK) continue;
                idcell_node_peer_label(c->host, &d, label, sizeof(label));
                printf("  %-24s 阶段 %s\n", label,
                       idcell_node_peer_stage_name(c->host, &d));
            }
        }
        return 1;
    }

    idcell_node_peer_label(c->host, &did, label, sizeof(label));
    printf("已绑定：%s\n", label);
    if (idcell_node_get_contract(c->host, &did, &ct) == IDCELL_OK)
        print_contract(&ct);
    return 0;
}

/* monitor：绑定后持续打印数据流 */
static int cmd_monitor(cli_ctx_t *c, const cli_args_t *a)
{
    idcell_did_t did;
    uint32_t deadline;

    if (wait_bound(c, a, &did) != IDCELL_OK) {
        printf("绑定失败，无法监控。\n");
        return 1;
    }
    {
        char label[IDCELL_MAX_LABEL];
        idcell_node_peer_label(c->host, &did, label, sizeof(label));
        printf("监控 %s（%ums）…\n", label, a->duration_ms);
    }

    deadline = now_ms() + a->duration_ms;
    while (now_ms() < deadline) {
        cli_poll(c, now_ms());
        sleep_ms(10);
    }
    printf("监控结束。\n");
    return 0;
}

/* write：绑定后发起写，等异步裁决 */
static int cmd_write(cli_ctx_t *c, const cli_args_t *a)
{
    idcell_did_t did;
    uint32_t token = 0;
    uint32_t deadline;
    int rc;

    if (wait_bound(c, a, &did) != IDCELL_OK) {
        printf("绑定失败，无法写。\n");
        return 1;
    }
    if (idcell_node_owner_token(c->host, &did, &token) != IDCELL_OK) {
        printf("取不到 owner_token，写被拒。\n");
        return 1;
    }

    printf("发起写：index=0x%04X value=%.4f intent=\"%s\"\n",
           a->index, a->value, a->intent ? a->intent : "");
    rc = idcell_node_write(c->host, a->index, a->sub, a->value, token, a->intent);
    printf("  本地预检：%s\n", idcell_err_name((idcell_err_t)rc));
    if (rc != IDCELL_OK) return 1;

    printf("  等待提供方裁决…\n");
    deadline = now_ms() + 2000;
    while (now_ms() < deadline) {
        cli_poll(c, now_ms());
        sleep_ms(10);
    }
    return 0;
}

/* ---------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    cli_args_t a;
    cli_ctx_t ctx;
    int rc, i;

    memset(&a, 0, sizeof(a));
    a.baud = 115200;
    a.want_ms = 20;
    a.stale_ms = 500;
    a.duration_ms = 5000;
    a.timeout_ms = 8000;
    a.sub = 0;

#ifdef _WIN32
    /* 控制台按 UTF-8 输出，保证中文提示与意图串可读 */
    SetConsoleOutputCP(CP_UTF8);
    /* 取 UTF-8 版 argv（绕开 CRT 的 ANSI 转换） */
    {
        char **uargv = NULL;
        int uargc = 0;
        if (cli_utf8_argv(&uargc, &uargv) == 0) {
            argc = uargc;
            argv = uargv;
        }
    }
#endif

    if (argc < 2) { usage(); return 1; }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) { usage(); return 0; }
    a.cmd = argv[1];

    for (i = 2; i < argc; i++) {
        const char *k = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;

        if (strcmp(k, "--port") == 0 && v) { a.port = v; i++; }
        else if (strcmp(k, "--device") == 0 && v) { a.device = v; i++; }
        else if (strcmp(k, "--qty") == 0 && v) { a.qty = v; i++; }
        else if (strcmp(k, "--unit") == 0 && v) { a.unit = v; i++; }
        else if (strcmp(k, "--intent") == 0 && v) { a.intent = v; i++; }
        else if (strcmp(k, "--loopback") == 0) { a.loopback = 1; }
        else if (strcmp(k, "--baud") == 0 && v) { parse_u32(v, &a.baud); i++; }
        else if (strcmp(k, "--want-ms") == 0 && v) { parse_u32(v, &a.want_ms); i++; }
        else if (strcmp(k, "--stale-ms") == 0 && v) { parse_u32(v, &a.stale_ms); i++; }
        else if (strcmp(k, "--timeout") == 0 && v) { parse_u32(v, &a.timeout_ms); i++; }
        else if (strcmp(k, "--duration") == 0 && v) { parse_u32(v, &a.duration_ms); i++; }
        else if (strcmp(k, "--index") == 0 && v) { uint32_t t; parse_u32(v, &t); a.index = (uint16_t)t; i++; }
        else if (strcmp(k, "--sub") == 0 && v) { uint32_t t; parse_u32(v, &t); a.sub = (uint8_t)t; i++; }
        else if (strcmp(k, "--value") == 0 && v) { parse_double(v, &a.value); i++; }
        else if (strcmp(k, "-h") == 0 || strcmp(k, "--help") == 0) { usage(); return 0; }
        else {
            fprintf(stderr, "未知选项：%s\n", k);
            usage();
            return 1;
        }
    }

    if (strcmp(a.cmd, "scan") != 0 && strcmp(a.cmd, "match") != 0 &&
        strcmp(a.cmd, "bind") != 0 && strcmp(a.cmd, "monitor") != 0 &&
        strcmp(a.cmd, "write") != 0) {
        fprintf(stderr, "未知子命令：%s\n", a.cmd);
        usage();
        return 1;
    }

    /* 除 scan 外都要一条需求——需求描述与设备身份解耦（FR-011） */
    if (strcmp(a.cmd, "scan") != 0 && (!a.qty || !a.unit)) {
        fprintf(stderr, "错误：%s 需要 --qty 与 --unit 描述你要什么。\n", a.cmd);
        fprintf(stderr, "      --qty  是量种名（acceleration / force / temperature …）\n");
        fprintf(stderr, "      --unit 是 UCUM 规范码（m/s2 / N / Cel …）\n");
        fprintf(stderr, "      设备身份由发现过程给出，不需要在命令行里写 DID。\n");
        return 1;
    }
    if (strcmp(a.cmd, "write") == 0 && !a.intent) {
        fprintf(stderr, "错误：write 需要 --intent 说明意图（SEC-019：写必须带意图结构）。\n");
        return 1;
    }

    rc = cli_setup(&ctx, &a);
    if (rc != IDCELL_OK) { cli_ctx_free(&ctx); return 1; }

    if (strcmp(a.cmd, "scan") == 0)        rc = cmd_scan(&ctx, &a);
    else if (strcmp(a.cmd, "match") == 0)  rc = cmd_bind(&ctx, &a);
    else if (strcmp(a.cmd, "bind") == 0)   rc = cmd_bind(&ctx, &a);
    else if (strcmp(a.cmd, "monitor") == 0) rc = cmd_monitor(&ctx, &a);
    else if (strcmp(a.cmd, "write") == 0)  rc = cmd_write(&ctx, &a);

    cli_ctx_free(&ctx);
    return rc;
}
