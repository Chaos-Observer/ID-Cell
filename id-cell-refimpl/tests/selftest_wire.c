/*
 * ID-CELL · 一致性套件的黑盒层（v0.11 新增）
 * ============================================================================
 *
 * 这个文件是 §15.7 第二个待拍板项（「参考实现与一致性套件是否同一份代码」）
 * 的落地产物。
 *
 * 问题的原话：
 *   「若套件直接调用参考实现的函数，则套件只能验证『参考实现符合参考实现』。
 *    第三方实现无法用它对照，因为套件与被测对象共用同一套内部逻辑；
 *    真正的价值在于套件的断言应针对线上可见的帧与字节，而不是内部函数返回值。」
 *
 * 因此本文件与 selftest.c 是**两份物理分离**的代码：
 *
 *   selftest.c        内部层：断言内部函数返回值、节点内部状态、契约结构体。
 *                     它验证的是参考实现的**自洽性**，快且定位准。
 *   selftest_wire.c   黑盒层：断言链路上真实出现过的**字节**。
 *                     它验证的是参考实现的**符合性**，且第三方实现可以照抄。
 *
 * 本文件的硬约束：
 *   1. 只 include "idcell.h" 与 "idcell_transport.h"——**禁止** include
 *      "idcell_internal.h"。一旦 include 了内部头，「黑盒」二字立即失效，
 *      因为断言就会依赖参考实现的内部结构。
 *   2. 帧解析与 CRC 计算由 idcell_wire_probe.h 独立提供，不调用
 *      idcell_frame_decode / idcell_crc16。
 *   3. 断言只用公开 API 取数据（idcell_node_* 与 idcell_loopback_*），
 *      线上字节一律从探针的 wire 缓冲里取。
 *
 * 断言分层（与 §11.3 新增的可见性三层对应）：
 *
 *   L1 内部层    断言内部函数返回值。快，但只对参考实现有意义。
 *   L2 字节层    断言线上字节。本文件的主体。
 *   L3 行为层    断言端到端可观察行为（回调、错误码、契约语义）。
 *
 * L2 是第三方实现唯一能直接复用的层——因为它的判据只有「线上出现了什么字节」。
 *
 * 方向约定（§09.1 的 SEQ 每方向独立递增，故线缆字节必须分方向断言）：
 *   主机 TX：DISCOVER / MATCH / NEGOTIATE / AUTH / BIND / WRITE / READ
 *   设备 TX：HELLO / DONE / ERROR / EVENT / HEARTBEAT
 */
#include "idcell.h"
#include "idcell_transport.h"
#include "idcell_wire_probe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- 断言 */

static int g_pass = 0;
static int g_fail = 0;

static void group(const char *name)
{
    printf("\n[%s]\n", name);
}

static void ok(int cond, const char *what)
{
    if (cond) {
        g_pass++;
        printf("  PASS  %s\n", what);
    } else {
        g_fail++;
        printf("  FAIL  %s\n", what);
    }
}

static void ok_eq(int got, int want, const char *what)
{
    if (got == want) {
        g_pass++;
        printf("  PASS  %s\n", what);
    } else {
        g_fail++;
        printf("  FAIL  %s   (期望 %d，实际 %d)\n", what, want, got);
    }
}

/* ---------------------------------------------------------------- 仿真设备 */

typedef struct {
    double accel;
    double temp;
    int    set_calls;
    double last_set_value;
    uint64_t tick;
} dev_state_t;

static int dev_read(void *ud, uint16_t index, uint8_t sub,
                    double *value, uint64_t *ts_us, idcell_prov_t *prov)
{
    dev_state_t *d = (dev_state_t *)ud;
    (void)sub;
    if (index == 0x0100)      *value = d->accel;
    else if (index == 0x0200) *value = d->temp;
    else return IDCELL_E_NODEV;
    *ts_us = d->tick * 5000;
    *prov = IDCELL_PROV_MEASURED;
    return IDCELL_OK;
}

static int dev_write(void *ud, uint16_t index, uint8_t sub,
                     double value, const char *intent, uint32_t owner_token)
{
    dev_state_t *d = (dev_state_t *)ud;
    (void)sub; (void)intent; (void)owner_token;
    d->set_calls++;
    d->last_set_value = value;
    if (index == 0x0200) d->temp = value;
    return IDCELL_OK;
}

/* ---------------------------------------------------------------- 场景搭建 */

/*
 * 一个被观测的链路场景：设备 + 主机 + 两端探针。
 *
 * 把「搭场景」抽成函数是必要的——本文件要跑六组独立场景，
 * 若每组都复制一遍 60 行搭建代码，测试代码本身就会成为维护负担，
 * 而测试代码的维护负担最终会变成「不敢改断言」的理由。
 */
typedef struct {
    idcell_loopback_t *lb;
    idwp_link_t  link_a;      /* 设备侧探针 */
    idwp_link_t  link_b;      /* 主机侧探针 */
    idcell_node_t *dev;
    idcell_node_t *host;
    dev_state_t  st;
    idcell_did_t dev_did;
    idcell_did_t host_did;
    uint32_t     now;

    /* v0.12：设备时钟源的模拟参数（§26） */
    uint64_t     clock_base_ns;
    uint16_t     clock_epoch;
    uint8_t      clock_quality;
} scene_t;

/* 需求类型：加速度（只读，范围宽）或温度（读写，范围窄） */
typedef enum { REQ_ACCEL, REQ_TEMP } req_kind_t;

static void scene_free(scene_t *sc)
{
    if (sc->dev)  idcell_node_free(sc->dev);
    if (sc->host) idcell_node_free(sc->host);
    if (sc->lb)   idcell_loopback_free(sc->lb);
    memset(sc, 0, sizeof(*sc));
}

/* v0.12：设备本地计数源。counter 单位 = tick_ns = 1 µs。 */
static int wire_dev_clock(void *ud, idcell_clock_sample_t *out)
{
    scene_t *sc = (scene_t *)ud;
    out->counter = sc->clock_base_ns / 1000ULL + (uint64_t)sc->now * 1000ULL;
    out->tick_ns = 1000;
    out->epoch = sc->clock_epoch;
    out->quality = sc->clock_quality;
    return IDCELL_OK;
}

/*
 * 搭建场景并跑完管道。
 * 返回 1 表示绑定成功。
 */
static int scene_setup(scene_t *sc, req_kind_t kind)
{
    idcell_transport_t tr_a, tr_b;
    idcell_node_cfg_t cfg;
    idcell_capability_t cap;
    idcell_requirement_t req;
    idcell_did_t p;
    int i;

    memset(sc, 0, sizeof(*sc));

    sc->lb = idcell_loopback_new();
    if (!sc->lb) return 0;
    idcell_loopback_endpoints(sc->lb, &tr_a, &tr_b);
    idwp_link_init(&sc->link_a, &tr_a);
    idwp_link_init(&sc->link_b, &tr_b);

    /* --- 设备侧 --- */
    memset(&sc->st, 0, sizeof(sc->st));
    {
        idcell_node_cfg_t dcfg;
        memset(&dcfg, 0, sizeof(dcfg));
        idcell_did_generate(0x4444, &dcfg.did);
        memset(dcfg.cred, 0x5A, sizeof(dcfg.cred));
        dcfg.max_perm = IDCELL_PERM_P2;
        dcfg.proficiency = 2;
        dcfg.t_hb_ms = 1000;
        dcfg.lease_ttl_ms = 3000;
        dcfg.announce_ms = 200;
        snprintf(dcfg.vendor, sizeof(dcfg.vendor), "Acme");
        snprintf(dcfg.model, sizeof(dcfg.model), "IMU-6DOF");

        sc->dev = idcell_node_new(&dcfg);
        idcell_node_set_transport(sc->dev, &sc->link_a.tap);
    }

    memset(&cap, 0, sizeof(cap));
    cap.index = 0x0100;
    snprintf(cap.label, sizeof(cap.label), "imu.accel.x");
    cap.qty = IDCELL_QTY_ACCELERATION;
    snprintf(cap.unit, sizeof(cap.unit), "m/s2");
    cap.accept_count = 1;
    snprintf(cap.accept_units[0], sizeof(cap.accept_units[0]), "m/s2");
    cap.dir = IDCELL_DIR_R;
    cap.perm = IDCELL_PERM_P1;
    cap.conv_class = IDCELL_CONV_T1;
    cap.dtype = IDCELL_DTYPE_F64;
    cap.scale_exp = 0;
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_I32, 3);
    cap.range[0] = -160.0;
    cap.range[1] = 160.0;
    cap.precision = 0.001;
    cap.min_sync_ms = 20;
    cap.stale_ms = 500;
    cap.fail_action = IDCELL_FAIL_HOLD;
    idcell_node_register_capability(sc->dev, &cap);

    memset(&cap, 0, sizeof(cap));
    cap.index = 0x0200;
    snprintf(cap.label, sizeof(cap.label), "imu.temperature");
    cap.qty = IDCELL_QTY_TEMPERATURE;
    snprintf(cap.unit, sizeof(cap.unit), "Cel");
    cap.accept_count = 1;
    snprintf(cap.accept_units[0], sizeof(cap.accept_units[0]), "Cel");
    cap.dir = IDCELL_DIR_RW;
    cap.perm = IDCELL_PERM_P2;
    cap.conv_class = IDCELL_CONV_T1;
    cap.dtype = IDCELL_DTYPE_F64;
    cap.scale_exp = 0;
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_type_list_add(cap.accept_types, &cap.accept_type_count, IDCELL_DTYPE_I16, 2);
    cap.range[0] = -40.0;
    cap.range[1] = 85.0;
    cap.precision = 0.01;
    cap.min_sync_ms = 200;
    cap.stale_ms = 2000;
    cap.fail_action = IDCELL_FAIL_HOLD;
    idcell_node_register_capability(sc->dev, &cap);

    sc->st.accel = 0.12;
    sc->st.temp = 27.5;
    sc->st.tick = 1;
    idcell_node_set_value_source(sc->dev, dev_read, &sc->st);
    idcell_node_set_setter(sc->dev, dev_write, &sc->st);

    /* --- 主机侧 --- */
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(0x5555, &cfg.did);
    memset(cfg.cred, 0x5A, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.proficiency = 2;
    cfg.t_hb_ms = 1000;
    cfg.lease_ttl_ms = 3000;
    cfg.announce_ms = 200;
    snprintf(cfg.vendor, sizeof(cfg.vendor), "Robotics");
    snprintf(cfg.model, sizeof(cfg.model), "ArmCtrl");

    sc->host = idcell_node_new(&cfg);
    idcell_node_set_transport(sc->host, &sc->link_b.tap);

    sc->dev_did  = idcell_node_did(sc->dev);
    sc->host_did = idcell_node_did(sc->host);

    memset(&req, 0, sizeof(req));
    req.index = 0xFFFF;
    req.kind = IDCELL_KIND_STATE;
    if (kind == REQ_ACCEL) {
        snprintf(req.label, sizeof(req.label), "机器人要的加速度");
        req.qty = IDCELL_QTY_ACCELERATION;
        snprintf(req.unit, sizeof(req.unit), "m/s2");
        snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "m/s2");
        req.perm = IDCELL_PERM_P1;
        idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_I32, 3);
        req.want_ms = 20;
        req.stale_ms = 500;
    } else {
        snprintf(req.label, sizeof(req.label), "机器人要的温度");
        req.qty = IDCELL_QTY_TEMPERATURE;
        snprintf(req.unit, sizeof(req.unit), "Cel");
        snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "Cel");
        req.perm = IDCELL_PERM_P2;
        idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_I16, 2);
        req.want_ms = 200;
        req.stale_ms = 2000;
    }
    req.accept_count = 1;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_node_register_requirement(sc->host, &req);

    /* --- 跑管道 --- */
    for (i = 0; i < 600; i++) {
        idcell_node_poll(sc->dev, sc->now);
        idcell_node_poll(sc->host, sc->now);
        sc->now += 10;
        if (idcell_node_peer_count(sc->host) > 0) {
            idcell_node_peer(sc->host, 0, &p);
            if (idcell_node_get_contract(sc->host, &p, &(idcell_contract_t){0}) == IDCELL_OK) {
                return 1;
            }
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- 12. 黑盒 */

/*
 * 12.1 帧结构合规：探针用独立解析器与独立 CRC 核对线上字节（§09.1 / §08.12）
 */
static void test_wire_frame_structure(void)
{
    scene_t sc;
    int found = 0, crc_bad = 0, seq_bad = 0, len_bad = 0, layout_bad = 0;
    uint16_t last_seq = 0;
    int have_last = 0;
    idwp_frame_t g;

    group("12.1 黑盒·帧结构与 CRC（独立解析器核对线上字节）");

    if (!scene_setup(&sc, REQ_ACCEL)) {
        ok(0, "前置：管道跑通");
        scene_free(&sc);
        return;
    }
    ok(1, "前置：管道跑通");

    /* 主机侧 TX 方向：SEQ 每方向独立递增 */
    while (idwp_stream_next(&sc.link_b.tx, &g)) {
        found++;
        if (!g.crc_ok) crc_bad++;
        if (g.payload_len > IDCELL_MAX_PAYLOAD) len_bad++;
        if (idwp_get_u16(sc.link_b.tx.last + IDWP_OFF_LEN) != g.payload_len ||
            g.raw_len != IDWP_HDR_LEN + g.payload_len + g.auth_tag_len + IDWP_TRAILER_LEN)
            layout_bad++;
        if (have_last) {
            uint16_t expect = (uint16_t)(last_seq + 1);
            if (g.seq != expect) seq_bad++;
        }
        last_seq = g.seq;
        have_last = 1;
    }

    ok(found > 0, "探针从主机侧线上字节中解出帧");
    ok_eq(crc_bad, 0, "线上每一帧的 CRC16 与独立计算值一致（覆盖头+payload+可选AUTH_TAG）");
    ok_eq(len_bad, 0, "线上帧载荷长度均在单帧上限内");
    ok_eq(layout_bad, 0, "线上 LEN 与 36B头+payload+可选TAG+4B尾的精确帧长一致");
    ok_eq(seq_bad, 0, "线上帧 SEQ 按方向严格递增（§09.1）");

    /* 设备侧 TX 方向同样核对 CRC */
    {
        int n = 0, bad = 0;
        while (idwp_stream_next(&sc.link_a.tx, &g)) {
            n++;
            if (!g.crc_ok) bad++;
        }
        ok(n > 0, "探针从设备侧线上字节中解出帧");
        ok_eq(bad, 0, "设备侧线上帧的 CRC16 同样与独立计算值一致");
    }

    scene_free(&sc);
}

/*
 * 12.2 六段管道在线上留下了哪些帧（§08.1）
 */
static void test_wire_pipeline_frames(void)
{
    scene_t sc;
    unsigned hx[256], dx[256];

    group("12.2 黑盒·六段管道的线上痕迹（§08.1）");

    if (!scene_setup(&sc, REQ_ACCEL)) {
        ok(0, "前置：管道跑通");
        ok(0, "主机侧线上出现过 MATCH 帧");
        ok(0, "主机侧线上出现过 NEGOTIATE 帧");
        ok(0, "主机侧线上出现过 AUTH 帧");
        ok(0, "主机侧线上出现过 BIND 帧");
        ok(0, "设备侧线上出现过 HELLO 帧");
        scene_free(&sc);
        return;
    }
    ok(1, "前置：管道跑通");

    /* 一次遍历统计两个方向的全部帧类型 */
    idwp_count_all(&sc.link_b.tx, hx);
    idwp_count_all(&sc.link_a.tx, dx);

    ok(hx[IDWP_T_MATCH] >= 1,     "主机侧线上出现过 MATCH 帧");
    ok(hx[IDWP_T_NEGOTIATE] >= 1, "主机侧线上出现过 NEGOTIATE 帧");
    ok(hx[IDWP_T_AUTH] >= 1,      "主机侧线上出现过 AUTH 帧");
    ok(hx[IDWP_T_BIND] >= 1,      "主机侧线上出现过 BIND 帧");
    ok(dx[IDWP_T_HELLO] >= 1,     "设备侧线上出现过 HELLO 帧");

    scene_free(&sc);
}

/*
 * 12.3 能力描述符在线上的字节形态（§09.2 / §24.2 / §24.4 / §24.8）
 */
static void test_wire_descriptor(void)
{
    scene_t sc;
    idwp_frame_t f;
    idwp_tlv_t capd, t;

    group("12.3 黑盒·能力描述符的线上字段（§09.2 / §24）");

    if (!scene_setup(&sc, REQ_ACCEL)) {
        ok(0, "前置：管道跑通");
        ok(0, "HELLO 帧载荷含能力描述符 TLV");
        ok(0, "能力描述符含量种 ID 字段（§24.2）");
        ok(0, "能力描述符含单位码字段");
        ok(0, "能力描述符含值类型字段（§24.4）");
        ok(0, "能力描述符含可接受值类型字段（§24.8）");
        scene_free(&sc);
        return;
    }
    ok(1, "前置：管道跑通");

    if (idwp_find_frame(&sc.link_a.tx, IDWP_T_HELLO, &f) &&
        idwp_payload_find_tlv(f.payload, f.payload_len, IDWP_TLV_CAP_DESC, &capd)) {

        int has_qty = 0, has_unit = 0, has_dtype = 0, has_accept_t = 0;
        uint16_t dpos = 0;

        ok(1, "HELLO 帧载荷含能力描述符 TLV");

        while (idwp_tlv_next(capd.val, capd.len, &dpos, &t) == 0) {
            if (t.type == IDWP_CF_DIM)       has_qty = 1;
            if (t.type == IDWP_CF_UNIT)      has_unit = 1;
            if (t.type == IDWP_CF_DTYPE)     has_dtype = 1;
            if (t.type == IDWP_CF_ACCEPT_T) has_accept_t = 1;
        }
        ok(has_qty,      "能力描述符含量种 ID 字段（§24.2）");
        ok(has_unit,     "能力描述符含单位码字段");
        ok(has_dtype,    "能力描述符含值类型字段（§24.4）");
        ok(has_accept_t, "能力描述符含可接受值类型字段（§24.8）");
    } else {
        ok(0, "HELLO 帧载荷含能力描述符 TLV");
        ok(0, "能力描述符含量种 ID 字段（§24.2）");
        ok(0, "能力描述符含单位码字段");
        ok(0, "能力描述符含值类型字段（§24.4）");
        ok(0, "能力描述符含可接受值类型字段（§24.8）");
    }

    scene_free(&sc);
}

/*
 * 12.4 帧头字段合规（§09.1 / SEC-064）
 */
static void test_wire_header(void)
{
    scene_t sc;
    idwp_frame_t g;
    int n = 0, ver_bad = 0, prof_bad = 0, src_bad = 0, dst_bad = 0, group_bad = 0;
    uint8_t broadcast[8];
    memset(broadcast, IDWP_BROADCAST_BYTE, 8);

    group("12.4 黑盒·帧头字段合规（§09.1）");

    if (!scene_setup(&sc, REQ_ACCEL)) {
        ok(0, "前置：管道跑通");
        ok(0, "线上帧 VER 等于协议版本字节");
        ok(0, "线上帧 PROF 取值在 §08.12 的模式枚举内");
        ok(0, "线上帧 SRC 是发送方自己的 DID（SEC-064）");
        ok(0, "线上帧 DST 是接收方 DID 或广播地址");
        ok(0, "单播帧的 GROUP 为 0（§09.1）");
        scene_free(&sc);
        return;
    }
    ok(1, "前置：管道跑通");

    while (idwp_stream_next(&sc.link_b.tx, &g)) {
        n++;
        if (g.ver != (uint8_t)(IDCELL_VERSION_MAJOR << 4 | IDCELL_VERSION_MINOR)) ver_bad++;
        if (g.prof > 1) prof_bad++;
        if (memcmp(g.src, sc.host_did.b, 8) != 0) src_bad++;
        if (memcmp(g.dst, sc.dev_did.b, 8) != 0 &&
            memcmp(g.dst, broadcast, 8) != 0) dst_bad++;
        if (g.group != 0) group_bad++;
    }

    ok(n > 0, "主机侧线上有帧可核对头字段");
    ok_eq(ver_bad,   0, "线上帧 VER 等于协议版本字节");
    ok_eq(prof_bad,  0, "线上帧 PROF 取值在 §08.12 的模式枚举内");
    ok_eq(src_bad,   0, "线上帧 SRC 是发送方自己的 DID（SEC-064）");
    ok_eq(dst_bad,   0, "线上帧 DST 是接收方 DID 或广播地址");
    ok_eq(group_bad, 0, "单播帧的 GROUP 为 0（§09.1）");

    scene_free(&sc);
}

/*
 * 12.5 错误路径在线上的字节形态（§09.6 / FR-035）
 */
static void test_wire_error_body(void)
{
    scene_t sc;
    idwp_frame_t f;
    idwp_tlv_t ec, elo, ehi, ev;
    idcell_did_t p;
    uint32_t token = 0;
    int i;

    group("12.5 黑盒·错误体的线上形态（§09.6 / FR-035）");

    if (!scene_setup(&sc, REQ_TEMP)) {
        ok(0, "前置：管道跑通");
        ok(0, "设备侧线上出现过 ERROR 帧");
        ok(0, "ERROR 帧载荷含错误体 TLV");
        ok(0, "错误体携带错误码字段");
        ok(0, "错误体携带值域上下界（FR-035）");
        ok(0, "错误体携带实际值（FR-035）");
        scene_free(&sc);
        return;
    }
    ok(1, "前置：管道跑通");

    idcell_node_peer(sc.host, 0, &p);
    if (idcell_node_owner_token(sc.host, &p, &token) != IDCELL_OK) {
        ok(0, "设备侧线上出现过 ERROR 帧");
        ok(0, "ERROR 帧载荷含错误体 TLV");
        ok(0, "错误体携带错误码字段");
        ok(0, "错误体携带值域上下界（FR-035）");
        ok(0, "错误体携带实际值（FR-035）");
        scene_free(&sc);
        return;
    }

    /* 越界写：值域 [-40, 85] */
    idcell_node_write(sc.host, 0x0200, 0, 999.0, token, "越界写入");
    for (i = 0; i < 60; i++) {
        idcell_node_poll(sc.dev, sc.now);
        idcell_node_poll(sc.host, sc.now);
        sc.now += 10;
    }

    if (!idwp_find_frame(&sc.link_a.tx, IDWP_T_ERROR, &f) ||
        !idwp_payload_find_tlv(f.payload, f.payload_len, IDWP_TLV_ERR_BODY, &ec)) {
        ok(0, "设备侧线上出现过 ERROR 帧");
        ok(0, "ERROR 帧载荷含错误体 TLV");
        ok(0, "错误体携带错误码字段");
        ok(0, "错误体携带值域上下界（FR-035）");
        ok(0, "错误体携带实际值（FR-035）");
        scene_free(&sc);
        return;
    }

    ok(1, "设备侧线上出现过 ERROR 帧");
    ok(1, "ERROR 帧载荷含错误体 TLV（§09.6）");

    /*
     * 错误码：ERR_BODY TLV 的值就是错误码名（"E_RANGE"）。
     * §09.6 的「必须携带」清单规定的其余字段与 ERR_BODY **同级**，
     * 不是嵌套在它里面的——这一点从线上字节直接得到证实。
     */
    {
        char code[16];
        size_t n = ec.len < sizeof(code) - 1 ? ec.len : sizeof(code) - 1;
        memcpy(code, ec.val, n);
        code[n] = '\0';
        ok(strcmp(code, "E_RANGE") == 0, "错误体携带错误码 E_RANGE");
    }

    ok(idwp_payload_find_tlv(f.payload, f.payload_len, IDWP_TLV_ERR_RANGE_LO, &elo),
       "错误体携带值域下界（FR-035）");
    ok(idwp_payload_find_tlv(f.payload, f.payload_len, IDWP_TLV_ERR_RANGE_HI, &ehi),
       "错误体携带值域上界（FR-035）");
    ok(idwp_payload_find_tlv(f.payload, f.payload_len, IDWP_TLV_ERR_VALUE, &ev),
       "错误体携带实际值（FR-035）");

    /* 逐值核对：错误体里的值域与实际值必须与描述符声明一致 */
    if (elo.val && ehi.val && ev.val) {
        ok(idwp_get_f64(elo.val) == -40.0, "错误体中的值域下界为 -40");
        ok(idwp_get_f64(ehi.val) == 85.0,  "错误体中的值域上界为 85");
        ok(idwp_get_f64(ev.val) == 999.0,  "错误体中的实际值为 999");
    } else {
        ok(0, "错误体中的值域下界为 -40");
        ok(0, "错误体中的值域上界为 85");
        ok(0, "错误体中的实际值为 999");
    }

    /* 关键红线：越界的写 MUST NOT 触达设备（不截断、不钳位） */
    ok(sc.st.set_calls == 0,
       "越界的写没有触达设备——线上不得出现执行确认（§09.6 / FR-035）");

    scene_free(&sc);
}

/*
 * 12.6 写是异步的：WRITE 请求与裁决 MUST 是两个独立帧（FR-078 / §09.4）
 */
static void test_wire_async_write(void)
{
    scene_t sc;
    idwp_frame_t f;
    idwp_tlv_t t;
    idcell_did_t p;
    uint32_t token = 0;
    int i, has_write = 0, has_intent = 0, has_owner = 0;

    group("12.6 黑盒·写是异步的（FR-078 / §09.4）");

    if (!scene_setup(&sc, REQ_TEMP)) {
        ok(0, "前置：管道跑通");
        ok(0, "主机侧线上出现过 WRITE 帧");
        ok(0, "WRITE 帧携带意图串（SEC-019）");
        ok(0, "WRITE 帧携带 owner_token（SEC-019）");
        ok(0, "WRITE 帧与裁决不是同一帧");
        scene_free(&sc);
        return;
    }
    ok(1, "前置：管道跑通");

    idcell_node_peer(sc.host, 0, &p);
    if (idcell_node_owner_token(sc.host, &p, &token) != IDCELL_OK) {
        ok(0, "主机侧线上出现过 WRITE 帧");
        ok(0, "WRITE 帧携带意图串（SEC-019）");
        ok(0, "WRITE 帧携带 owner_token（SEC-019）");
        ok(0, "WRITE 帧与裁决不是同一帧");
        scene_free(&sc);
        return;
    }

    idcell_node_write(sc.host, 0x0200, 0, 26.5, token, "温漂补偿");
    for (i = 0; i < 40; i++) {
        idcell_node_poll(sc.dev, sc.now);
        idcell_node_poll(sc.host, sc.now);
        sc.now += 10;
    }

    if (idwp_find_frame(&sc.link_b.tx, IDWP_T_WRITE, &f)) {
        uint16_t pos = 0;
        has_write = 1;
        while (idwp_tlv_next(f.payload, f.payload_len, &pos, &t) == 0) {
            if (t.type == IDWP_TLV_INTENT) has_intent = 1;
            if (t.type == IDWP_TLV_OWNER)  has_owner = 1;
        }
        ok(1, "主机侧线上出现过 WRITE 帧");
        ok(has_intent, "WRITE 帧携带意图串（SEC-019）");
        ok(has_owner,  "WRITE 帧携带 owner_token（SEC-019）");
    } else {
        ok(0, "主机侧线上出现过 WRITE 帧");
        ok(0, "WRITE 帧携带意图串（SEC-019）");
        ok(0, "WRITE 帧携带 owner_token（SEC-019）");
    }

    /*
     * FR-078：发起接口的返回值不是裁决；最终裁决 MUST 经独立通道送达。
     * 线上证据：WRITE 帧里没有「裁决结果」字段——裁决走另一帧（DONE / ERROR）。
     */
    {
        idwp_frame_t g;
        int write_has_result = 0;
        while (idwp_stream_next(&sc.link_b.tx, &g)) {
            if (g.type == IDWP_T_WRITE) {
                uint16_t pos = 0;
                idwp_tlv_t tt;
                while (idwp_tlv_next(g.payload, g.payload_len, &pos, &tt) == 0) {
                    /* 0x34 = RESULT TLV：若出现在 WRITE 帧里，说明裁决与发起被合并了 */
                    if (tt.type == IDWP_TLV_RESULT) write_has_result = 1;
                }
            }
        }
        ok(!write_has_result, "WRITE 帧与裁决不是同一帧（FR-078）");
    }

    (void)has_write;
    scene_free(&sc);
}

/*
 * 12.7 v0.12 · §26：单跳时延测绘只使用既有 READ/READ 响应。
 *
 * 这一组是「内生」的字节层证据：没有新增帧类型、没有 SYNC 帧、
 * 没有改写 SRC/DST、没有把设备 TS 拉齐到发起端轴。补偿只发生在
 * 消费侧（读数补偿），线上两端各自保留自己的本地时刻。
 */
static void test_wire_clock(void)
{
    scene_t sc;
    idcell_clock_measure_t m;
    idwp_frame_t f, req_f, resp_f;
    uint8_t req_pay[256], resp_pay[256];
    uint16_t req_len = 0, resp_len = 0;
    unsigned ca[256] = { 0 }, cb[256] = { 0 };
    idwp_tlv_t ct, vt;
    uint64_t counter, mapped;
    uint32_t tick_ns, t0;
    uint16_t epoch;
    uint8_t quality;
    int i, ready = 0, have_req = 0, have_resp = 0, bad_type = 0;

    group("12.7 黑盒·时钟测量只走既有 READ（§26）");

    if (!scene_setup(&sc, REQ_ACCEL)) {
        ok(0, "前置：管道跑通");
        scene_free(&sc);
        return;
    }
    ok(1, "前置：管道跑通");

    sc.clock_base_ns = 50ULL * 1000ULL * 1000ULL;
    sc.clock_epoch = 3;
    sc.clock_quality = 2;
    idcell_node_set_clock_source(sc.dev, wire_dev_clock, &sc);

    t0 = sc.now;
    ok(idcell_node_measure_clock(sc.host, &sc.dev_did, t0) == IDCELL_OK,
       "测量请求以 READ 发出");

    for (i = 0; i < 20 && ready != 1; i++) {
        sc.now += 10;
        idcell_node_poll(sc.dev, sc.now);
        sc.now += 10;
        idcell_node_poll(sc.host, sc.now);
        ready = idcell_node_measure_clock_result(sc.host, &sc.dev_did, &m);
    }
    ok_eq(ready, 1, "测量在有限轮内完成");

    memset(req_pay, 0, sizeof(req_pay));
    memset(resp_pay, 0, sizeof(resp_pay));

    /* 主机 TX：统计类型并留取第一帧 READ */
    while (idwp_stream_next(&sc.link_b.tx, &f)) {
        cb[f.type]++;
        if (f.type > 0x18) bad_type = 1;
        if (f.type == IDWP_T_READ && !have_req) {
            req_f = f;
            req_len = f.payload_len;
            memcpy(req_pay, f.payload, req_len);
            have_req = 1;
        }
    }
    /* 设备 TX：统计类型并留取第一帧 READ 响应 */
    while (idwp_stream_next(&sc.link_a.tx, &f)) {
        ca[f.type]++;
        if (f.type > 0x18) bad_type = 1;
        if (f.type == IDWP_T_READ && !have_resp) {
            resp_f = f;
            resp_len = f.payload_len;
            memcpy(resp_pay, f.payload, resp_len);
            have_resp = 1;
        }
    }

    ok(have_req && cb[IDWP_T_READ] == 1, "主机 TX 恰好一帧 READ");
    ok(have_resp && ca[IDWP_T_READ] == 1, "设备 TX 恰好一帧 READ 响应");
    ok(!bad_type, "线上未出现既有类型表之外的帧类型（无新帧类型）");
    ok(req_f.crc_ok && resp_f.crc_ok, "请求与响应 CRC 均独立核对通过");

    ok(memcmp(req_f.src, sc.host_did.b, 8) == 0 &&
       memcmp(req_f.dst, sc.dev_did.b, 8) == 0,
       "请求 SRC/DST 仍是端到端身份");
    ok(memcmp(resp_f.src, sc.dev_did.b, 8) == 0 &&
       memcmp(resp_f.dst, sc.host_did.b, 8) == 0,
       "响应 SRC/DST 未被任何中间层改写");
    ok(req_f.txn == resp_f.txn, "请求与响应是同一事务号");

    ok(req_f.ts_us == (uint64_t)t0 * 1000ULL, "请求 TS 是发起端本地时刻");
    ok(resp_f.ts_us > req_f.ts_us &&
       resp_f.ts_us - req_f.ts_us <= 50000ULL,
       "响应 TS 是设备本地时刻，未被拉齐到发起端轴");

    ok(idwp_payload_find_tlv(req_pay, req_len, IDWP_TLV_VALUE, &vt) &&
       vt.idx == IDCELL_SVC_CLOCK_INDEX,
       "请求读的是 0xFE00 保留服务点");
    ok(!idwp_payload_find_tlv(req_pay, req_len, IDWP_TLV_CLOCK, NULL),
       "请求不携带 CLOCK 回传");
    ok(idwp_payload_find_tlv(resp_pay, resp_len, IDWP_TLV_CLOCK, &ct) &&
       ct.len == 15,
       "响应携带 15 字节 CLOCK 记录");
    ok(!idwp_payload_find_tlv(resp_pay, resp_len, IDWP_TLV_VALUE, NULL),
       "服务响应不是能力点读数（无 VALUE TLV）");

    counter  = idwp_get_u64(ct.val);
    tick_ns  = idwp_get_u32(ct.val + 8);
    epoch    = idwp_get_u16(ct.val + 12);
    quality  = ct.val[14];
    ok(tick_ns == 1000, "tick_ns 由设备声明（1 µs）");
    ok(epoch == 3, "epoch 原样回传");
    ok(quality == 2, "quality 原样回传");
    ok(counter == sc.clock_base_ns / 1000ULL + resp_f.ts_us,
       "counter 与设备本地时刻同源，不是被改写过的全局时间");

    ok(m.rtt_ns == 20000000ULL, "RTT 由发起端单侧时钟量得（20 ms）");
    ok(m.offset_ns > 49000000LL && m.offset_ns < 51000000LL,
       "offset ≈ 设备轴领先 50 ms");
    ok(m.epoch == 3 && m.tick_ns == 1000 && m.quality == 2,
       "测量结果保留设备的计数域声明");

    mapped = (uint64_t)idcell_clock_map_ns(&m, counter);
    ok(mapped >= resp_f.ts_us * 1000ULL - 1000000ULL &&
       mapped <= resp_f.ts_us * 1000ULL + 1000000ULL,
       "读数补偿把设备计数映射回发起端轴");

    scene_free(&sc);
}

/* ---------------------------------------------------------------- main */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("========================================================================\n");
    printf(" ID-CELL 一致性套件 · 黑盒层（只判线上字节）\n");
    printf("========================================================================\n");

    test_wire_frame_structure();
    test_wire_pipeline_frames();
    test_wire_descriptor();
    test_wire_header();
    test_wire_error_body();
    test_wire_async_write();
    test_wire_clock();

    printf("\n========================================================================\n");
    printf(" 通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    printf("========================================================================\n");
    return g_fail == 0 ? 0 : 1;
}
