/*
 * ID-CELL 快速应用示例（quickstart）
 * ============================================================================
 *
 * 场景：一台「惯性测量单元（IMU）」作为提供方，一台「机器人控制器」作为
 * 需求方。机器人需要 IMU 的加速度分量。示例跑完 ID-CELL 的六段管道，
 * 拿到绑定契约，并消费实时数据流、发起一次带意图的写操作。
 *
 * 这个文件同时是 §11.3 一致性套件的「黄金参考实现」：任何语言的其它
 * 实现，只要能让本文件的三条断言成立，就说明它跑通了管道、协商、
 * 授权与绑定这四件事。
 *
 * 编译（Windows，用 zig 自带的 clang）：
 *     python -m ziglang cc -std=c99 -Iinclude -o quickstart.exe ^
 *         examples\quickstart.c src\*.c
 *
 * 运行：
 *     quickstart.exe
 *
 * ---------------------------------------------------------------------------
 * 本示例刻意只依赖公开头文件 idcell.h——用户接入协议时看到的也只有这个文件。
 * ============================================================================
 */
#include "idcell.h"
#include "idcell_transport.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

/* ---------------------------------------------------------------- 虚拟 IMU */

typedef struct {
    double  accel_x;      /* m/s^2 */
    double  accel_y;
    double  accel_z;
    double  temperature;  /* degC */
    uint64_t tick;        /* 仿真时钟：每个采样 +1 */
} imu_state_t;

/* 提供方取值回调：协议层问「这个点现在是多少」 */
static int imu_read(void *ud, uint16_t index, uint8_t sub,
                    double *value, uint64_t *ts_us, idcell_prov_t *prov)
{
    imu_state_t *imu = (imu_state_t *)ud;
    (void)sub;
    switch (index) {
    case 0x0100: *value = imu->accel_x; break;
    case 0x0101: *value = imu->accel_y; break;
    case 0x0102: *value = imu->accel_z; break;
    case 0x0200: *value = imu->temperature; break;
    default: return IDCELL_E_NODEV;
    }
    *ts_us = imu->tick * 5000;    /* 200 Hz 采样 */
    *prov = IDCELL_PROV_MEASURED;
    return IDCELL_OK;
}

/* 提供方写入回调：被授权的写请求到达时调用（意图串与令牌一并交回） */
static int imu_write(void *ud, uint16_t index, uint8_t sub,
                     double value, const char *intent, uint32_t owner_token)
{
    imu_state_t *imu = (imu_state_t *)ud;
    (void)sub; (void)owner_token;
    printf("        [IMU] 收到写请求 index=0x%04X value=%.3f intent=\"%s\"\n",
           index, value, intent ? intent : "");
    if (index == 0x0200) imu->temperature = value;
    return IDCELL_OK;
}

/* 需求方数据回调：周期发布与 READ 应答都走这里 */
static void robot_on_data(void *ud, const idcell_did_t *peer,
                          uint16_t index, uint8_t sub, double value,
                          uint64_t ts_us, idcell_prov_t prov,
                          idcell_quality_t quality)
{
    char who[19];
    static const char *prov_name[] = { "measured", "estimated", "derived", "sampled" };
    static const char *qual_name[] = { "good", "uncertain", "bad" };
    (void)ud; (void)sub;
    idcell_did_str(peer, who);
    /* 来源（怎么来的）与质量（当下能不能用）是两回事，§24.5 */
    printf("        [机器人] %s  index=0x%04X  value=%.4f  ts=%lluus  来源=%s  质量=%s\n",
           who, index, value, (unsigned long long)ts_us,
           (prov < 4) ? prov_name[prov] : "unknown",
           (quality < 3) ? qual_name[quality] : "unknown");
}

/*
 * 需求方写结果回调：提供方的最终裁决经此送达。
 * idcell_node_write() 的返回值只代表「本地预检通过、请求已发出」，
 * 真正的写成功 / 越界拒绝 / 权限拒绝都在这里。
 */
static void robot_on_write_result(void *ud, const idcell_did_t *peer,
                                  uint16_t index, uint8_t sub,
                                  const idcell_write_result_t *res)
{
    (void)ud; (void)sub; (void)peer;
    printf("        [机器人] 写裁决 index=0x%04X -> %s",
           index, idcell_err_name((idcell_err_t)res->err));
    if (res->has_range)
        printf("（值 %.3f 超出值域 [%.3f, %.3f]）", res->value, res->range_lo, res->range_hi);
    else if (res->reason)
        printf("（%s）", res->reason);
    printf("\n");
}

/* ---------------------------------------------------------------- 注册助手 */

static void fill_cap(idcell_capability_t *c, uint16_t index, const char *label,
                     idcell_qty_t qty, const char *unit,
                     double lo, double hi, uint32_t min_sync_ms, uint32_t stale_ms)
{
    memset(c, 0, sizeof(*c));
    c->index        = index;
    c->sub          = 0;
    snprintf(c->label, sizeof(c->label), "%s", label);
    c->kind         = IDCELL_KIND_STATE;
    c->dir          = IDCELL_DIR_R;
    c->perm         = IDCELL_PERM_P1;
    c->qty          = qty;           /* v0.8：量种 ID */
    snprintf(c->unit, sizeof(c->unit), "%s", unit);   /* UCUM 码 */
    c->accept_count = 1;
    snprintf(c->accept_units[0], sizeof(c->accept_units[0]), "%s", unit);
    c->conv_class   = IDCELL_CONV_T1;
    c->dtype        = IDCELL_DTYPE_F64;
    c->scale_exp    = 0;
    /* v0.9：声明可接受值类型（§24.8）。本例接受原生 f64 与 i32×10^-3 两种编码 */
    idcell_type_list_add(c->accept_types, &c->accept_type_count,
                         IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(c->accept_types, &c->accept_type_count,
                         IDCELL_DTYPE_I32, 3);
    c->range[0]     = lo;
    c->range[1]     = hi;
    c->precision    = 0.001;
    c->min_sync_ms  = min_sync_ms;   /* T_prod */
    c->stale_ms     = stale_ms;      /* T_stale */
    c->trigger      = IDCELL_TRIG_LEVEL;
    c->fail_action  = IDCELL_FAIL_HOLD;
    c->provenance   = IDCELL_PROV_MEASURED;
}

static void fill_req(idcell_requirement_t *r, const char *label,
                     idcell_qty_t qty, const char *unit,
                     uint32_t want_ms, uint32_t stale_ms)
{
    memset(r, 0, sizeof(*r));
    snprintf(r->label, sizeof(r->label), "%s", label);
    r->qty          = qty;           /* v0.8：量种 ID */
    snprintf(r->unit, sizeof(r->unit), "%s", unit);   /* UCUM 码 */
    r->accept_count = 1;
    snprintf(r->accept_units[0], sizeof(r->accept_units[0]), "%s", unit);
    /* v0.9：需求方声明可接受值类型（§24.8） */
    idcell_type_list_add(r->accept_types, &r->accept_type_count,
                         IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(r->accept_types, &r->accept_type_count,
                         IDCELL_DTYPE_I32, 3);
    r->perm    = IDCELL_PERM_P1;
    r->index   = 0xFFFF;      /* 不限定能力点索引 */
    r->want_ms = want_ms;     /* T_want */
    r->stale_ms = stale_ms;    /* T_stale */
    r->kind    = IDCELL_KIND_STATE;
}

/* ---------------------------------------------------------------- 主流程 */

int main(void)
{
    idcell_loopback_t *lb;
    idcell_transport_t tr_a, tr_b;
    idcell_node_t *imu = NULL, *robot = NULL;
    idcell_node_cfg_t cfg;
    idcell_capability_t cap;
    idcell_requirement_t req;
    idcell_device_type_t dt;
    idcell_link_profile_t lb_profile;
    imu_state_t imu_state;
    idcell_did_t peer_did;
    uint32_t now = 0;
    int i, rc;

    /* 不缓冲输出：即使中途出错，已打印的部分也能被看到 */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("========================================================================\n");
    printf(" ID-CELL 快速应用示例：虚拟 IMU + 机器人控制器\n");
    printf(" v0.11 线格式：36B 固定头 + LEN payload + 可选16B AUTH_TAG + CRC + TRAILER\n");
    printf(" 六段管道 DISCOVER → DESCRIBE → MATCH → NEGOTIATE → AUTHORIZE → BIND\n");
    printf("========================================================================\n\n");

    /* ---------- 1. 物理链路 ---------- */
    lb = idcell_loopback_new();
    if (!lb) { printf("无法创建回环链路\n"); return 1; }
    idcell_loopback_endpoints(lb, &tr_a, &tr_b);
    lb_profile = *tr_a.profile;

    printf("[1] 物理链路\n");
    printf("    介质      = %s\n", idcell_media_name(lb_profile.media));
    printf("    拓扑      = %s\n", idcell_topology_name(lb_profile.topology));
    printf("    T_link_min= %u ms\n\n", lb_profile.t_link_min_ms);

    /* ---------- 2. 设备侧节点 ---------- */
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0xA1B2C3D4, &cfg.did);         /* 独立生成，与链路无关 */
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));          /* 演示用共享凭证 */
    cfg.max_perm     = IDCELL_PERM_P2;
    cfg.proficiency  = 2;
    cfg.t_hb_ms      = 1000;
    cfg.lease_ttl_ms = 3000;
    cfg.announce_ms  = 200;
    snprintf(cfg.vendor, sizeof(cfg.vendor), "Acme");
    snprintf(cfg.model,  sizeof(cfg.model),  "IMU-6DOF");

    imu = idcell_node_new(&cfg);
    if (!imu) { printf("节点创建失败\n"); return 1; }
    idcell_node_set_transport(imu, &tr_a);

    /* ---------- 3. 提供方注册能力（§09.2 必需轨） ---------- */
    printf("[2] 提供方注册能力点（能力描述符 = 能力的唯一权威）\n");

    fill_cap(&cap, 0x0100, "imu.accel.x", IDCELL_QTY_ACCELERATION, "m/s2", -160.0, 160.0, 20, 500);
    idcell_node_register_capability(imu, &cap);
    fill_cap(&cap, 0x0101, "imu.accel.y", IDCELL_QTY_ACCELERATION, "m/s2", -160.0, 160.0, 20, 500);
    idcell_node_register_capability(imu, &cap);
    fill_cap(&cap, 0x0102, "imu.accel.z", IDCELL_QTY_ACCELERATION, "m/s2", -160.0, 160.0, 20, 500);
    idcell_node_register_capability(imu, &cap);

    fill_cap(&cap, 0x0200, "imu.temperature", IDCELL_QTY_TEMPERATURE, "Cel", -40.0, 85.0, 200, 2000);
    cap.dir  = IDCELL_DIR_RW;                 /* 可写：允许机器人做零点偏置 */
    cap.perm = IDCELL_PERM_P2;                /* 写需要 P2 */
    idcell_node_register_capability(imu, &cap);

    /* 设备类型：可选轨。注册它不是能力注册的前提，只是给工具链看。 */
    memset(&dt, 0, sizeof(dt));
    snprintf(dt.type_name, sizeof(dt.type_name), "IMU-6DOF");
    snprintf(dt.vendor, sizeof(dt.vendor), "Acme");
    dt.model_id = 0x0A01;
    dt.version  = 3;
    snprintf(dt.capability_summary, sizeof(dt.capability_summary), "六轴惯导 + 温度");
    idcell_node_register_device_type(imu, &dt);

    printf("    已注册 4 个能力点，描述符版本 v%u\n", idcell_node_desc_version(imu));
    printf("    设备类型（可选轨）：%s v%u\n\n", dt.type_name, dt.version);

    imu_state.accel_x = 0.12; imu_state.accel_y = -0.03; imu_state.accel_z = 9.81;
    imu_state.temperature = 27.5; imu_state.tick = 1;
    idcell_node_set_value_source(imu, imu_read, &imu_state);
    idcell_node_set_setter(imu, imu_write, &imu_state);

    /* ---------- 4. 需求方注册需求 ---------- */
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x0BADF00D, &cfg.did);
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));
    cfg.max_perm     = IDCELL_PERM_P2;
    cfg.proficiency  = 2;
    cfg.t_hb_ms      = 1000;
    cfg.lease_ttl_ms = 3000;
    cfg.announce_ms  = 200;
    snprintf(cfg.vendor, sizeof(cfg.vendor), "Robotics");
    snprintf(cfg.model,  sizeof(cfg.model),  "ArmCtrl");

    robot = idcell_node_new(&cfg);
    if (!robot) { printf("节点创建失败\n"); return 1; }
    idcell_node_set_transport(robot, &tr_b);
    idcell_node_set_data_sink(robot, robot_on_data, NULL);
    idcell_node_set_write_result_sink(robot, robot_on_write_result, NULL);

    printf("[3] 需求方注册需求（只说「我要什么」，不含设备身份）\n");
    fill_req(&req, "机器人需要的加速度", IDCELL_QTY_ACCELERATION, "m/s2", 20, 500);
    idcell_node_register_requirement(robot, &req);
    printf("    需求：量=%s 单位=%s T_want=%ums T_stale=%ums\n",
           req.label, req.unit, req.want_ms, req.stale_ms);
    fill_req(&req, "机器人需要写入的温度", IDCELL_QTY_TEMPERATURE, "Cel", 200, 2000);
    req.perm = IDCELL_PERM_P2;
    idcell_node_register_requirement(robot, &req);
    printf("    需求：量=%s 单位=%s T_want=%ums T_stale=%ums（显式写契约）\n\n",
           req.label, req.unit, req.want_ms, req.stale_ms);

    /* ---------- 5. 跑管道 ---------- */
    printf("[4] 执行入口：反复调用 idcell_node_poll(node, now_ms)\n");
    printf("    （设备侧唯一入口；不得在中断上下文调用）\n\n");

    for (i = 0; i < 400; i++) {
        idcell_node_poll(imu, now);
        idcell_node_poll(robot, now);
        now += 10;

        if (i == 40) {
            /* 仿真 IMU 数据随时间变化，验证「值未更新就不发」这条红线 */
            imu_state.accel_x = 0.12 + 0.4 * sin(now / 400.0);
            imu_state.tick++;
        }
        if (i == 120) {
            imu_state.accel_x = 0.55;
            imu_state.tick++;
        }
        if (i == 200) break;
    }

    /* ---------- 6. 打印契约 ---------- */
    if (idcell_node_peer_count(robot) == 0) {
        printf("!! 没有发现任何对端，示例失败\n");
        return 1;
    }
    idcell_node_peer(robot, 0, &peer_did);

    {
        idcell_contract_t ct;
        char who[19];
        idcell_did_str(&peer_did, who);

        if (idcell_node_get_contract(robot, &peer_did, &ct) != IDCELL_OK) {
            printf("!! 绑定未完成（阶段 = %s）\n",
                   idcell_node_peer_stage_name(robot, &peer_did));
            return 1;
        }

        printf("[5] 绑定契约（§09.7 十字段，双方各持一份、冲突取更严者）\n");
        printf("    binding_id  = 0x%08X\n", ct.binding_id);
        printf("    peer_pair   = %s\n", who);
        printf("    cap_list    = %u 个能力点\n", ct.pt_count);
        printf("    per_point   :\n");
        for (i = 0; i < ct.pt_count; i++) {
            printf("        index=0x%04X sub=%u  unit=%-8s T_pub=%-4ums P%u  降级=%s\n",
                   ct.pt[i].index, ct.pt[i].sub, ct.pt[i].unit,
                   ct.pt[i].t_pub_ms, (unsigned)ct.pt[i].perm,
                   ct.pt[i].degrade == IDCELL_FAIL_HOLD ? "hold" :
                   ct.pt[i].degrade == IDCELL_FAIL_BRAKE ? "brake" :
                   ct.pt[i].degrade == IDCELL_FAIL_DAMP ? "damp" : "off");
        }
        printf("    arb_domain  = 0x%08X\n", ct.arb_domain);
        printf("    lease_ttl   = %ums\n", ct.lease_ttl_ms);
        /* SEC-067：完整 owner_token MUST NOT 出现在输出里，只给不可直接复用的短前缀 */
        {
            char masked[24];
            idcell_mask_token(ct.owner_token, masked, sizeof(masked));
            printf("    owner_token = %s\n", masked);
        }
        printf("    desc_version= %u\n", ct.desc_version);
        printf("    provenance  = %s\n\n",
               ct.pt_count ? ((ct.pt[0].prov == IDCELL_PROV_MEASURED) ? "measured（实测）" :
                              (ct.pt[0].prov == IDCELL_PROV_ESTIMATED) ? "estimated（估计）" :
                              (ct.pt[0].prov == IDCELL_PROV_DERIVED) ? "derived（推导）" :
                                                                      "sampled（采样）")
                           : "—");
    }

    /* ---------- 7. 数据流 ---------- */
    printf("[6] 实时数据流（周期发布；值未更新则不发，绝不重复旧值伪装刷新）\n");
    for (i = 0; i < 120; i++) {
        imu_state.accel_x = 0.55 + 0.3 * sin(now / 300.0);
        imu_state.tick++;
        idcell_node_poll(imu, now);
        idcell_node_poll(robot, now);
        now += 10;
    }
    printf("\n");

    /* ---------- 8. 写操作 ---------- */
    printf("[7] 写操作（SEC-019：必须携带 owner_token 与意图结构）\n");
    printf("    写是异步的：idcell_node_write() 只做本地预检并发出请求，\n");
    printf("    最终裁决由提供方做出，经写结果回调送达（见下方 [机器人] 行）。\n");
    {
        uint32_t token = 0;
        idcell_node_owner_token(robot, &peer_did, &token);

        rc = idcell_node_write(robot, 0x0200, 0, 26.0, token, "温漂补偿：写入零点偏置");
        printf("    ① 带令牌 + 带意图 -> 本地预检 %s\n", idcell_err_name((idcell_err_t)rc));
        for (i = 0; i < 20; i++) { idcell_node_poll(imu, now); idcell_node_poll(robot, now); now += 10; }

        rc = idcell_node_write(robot, 0x0200, 0, 26.0, token, NULL);
        printf("    ② 缺意图串        -> 本地预检 %s（本地直接拒绝，不会发出请求）\n",
               idcell_err_name((idcell_err_t)rc));

        rc = idcell_node_write(robot, 0x0200, 0, 26.0, token ^ 0xFFFFu, "伪造令牌");
        printf("    ③ 令牌不匹配      -> 本地预检 %s（本地直接拒绝）\n",
               idcell_err_name((idcell_err_t)rc));

        rc = idcell_node_write(robot, 0x0200, 0, 999.0, token, "越界写入");
        printf("    ④ 值越界（999）   -> 本地预检 %s（本地查不出值域，越界由提供方裁决）\n",
               idcell_err_name((idcell_err_t)rc));
        for (i = 0; i < 20; i++) { idcell_node_poll(imu, now); idcell_node_poll(robot, now); now += 10; }
    }

    printf("\n========================================================================\n");
    printf(" 管道跑通：DISCOVER → DESCRIBE → MATCH → NEGOTIATE → AUTHORIZE → BIND\n");
    printf("========================================================================\n");

    idcell_node_free(imu);
    idcell_node_free(robot);
    idcell_loopback_free(lb);
    return 0;
}
