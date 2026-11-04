/* P1-1 发现、休眠与 mailbox：真实 C 行为测试及 C<->Python 行为向量。 */
#include "idcell_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static int d_pass, d_fail;
static void dok(int cond, const char *name)
{
    if (cond) { d_pass++; printf("PASS %s\n", name); }
    else { d_fail++; printf("FAIL %s\n", name); }
}
static void deq(int got, int want, const char *name)
{
    if (got == want) { d_pass++; printf("PASS %s\n", name); }
    else { d_fail++; printf("FAIL %s got=%d want=%d\n", name, got, want); }
}

#define CAPTURE_MAX 96
typedef struct {
    uint8_t wire[CAPTURE_MAX][IDCELL_MAX_FRAME];
    size_t len[CAPTURE_MAX];
    uint32_t at[CAPTURE_MAX];
    int count;
    int fail_send;
    uint32_t now;
    idcell_link_profile_t profile;
} capture_t;

static int capture_send(void *ctx, const uint8_t *buf, size_t len)
{
    capture_t *c = (capture_t *)ctx;
    if (c->fail_send > 0) { c->fail_send--; return -1; }
    if (c->count >= CAPTURE_MAX || len > IDCELL_MAX_FRAME) return -1;
    memcpy(c->wire[c->count], buf, len);
    c->len[c->count] = len;
    c->at[c->count] = c->now;
    c->count++;
    return 0;
}
static int capture_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t timeout)
{
    (void)ctx; (void)buf; (void)cap; (void)timeout;
    return 0;
}
static void capture_clear(capture_t *c) { c->count = 0; }
static int capture_type(const capture_t *c, uint8_t type, int ordinal, idcell_frame_t *out)
{
    int i;
    size_t used;
    for (i = 0; i < c->count; i++) {
        if (c->wire[i][5] != type) continue;
        if (ordinal-- == 0) {
            if (idcell_frame_decode(c->wire[i], c->len[i], out, &used) < 0) return -1;
            return 0;
        }
    }
    return -1;
}
static int capture_count_type(const capture_t *c, uint8_t type)
{
    int i, count = 0;
    for (i = 0; i < c->count; i++) if (c->wire[i][5] == type) count++;
    return count;
}

static void fill_cap(idcell_capability_t *c)
{
    memset(c, 0, sizeof(*c));
    c->index = 0x0200;
    c->kind = IDCELL_KIND_STATE;
    c->dir = IDCELL_DIR_RW;
    c->perm = IDCELL_PERM_P2;
    c->qty = IDCELL_QTY_TEMPERATURE;
    snprintf(c->label, sizeof(c->label), "temperature");
    snprintf(c->unit, sizeof(c->unit), "Cel");
    c->accept_count = 1;
    snprintf(c->accept_units[0], sizeof(c->accept_units[0]), "Cel");
    c->conv_class = IDCELL_CONV_T1;
    c->dtype = IDCELL_DTYPE_F64;
    idcell_type_list_add(c->accept_types, &c->accept_type_count, IDCELL_DTYPE_F64, 0);
    c->range[0] = -40; c->range[1] = 85;
    c->min_sync_ms = 20; c->stale_ms = 1000;
    c->fail_action = IDCELL_FAIL_HOLD;
}

static idcell_node_t *make_node(uint64_t seed, int with_cap, capture_t *capture)
{
    idcell_node_cfg_t cfg;
    idcell_node_t *n;
    memset(&cfg, 0, sizeof(cfg));
    idcell_did_generate(seed, &cfg.did);
    memset(cfg.cred, 0x42, sizeof(cfg.cred));
    cfg.max_perm = IDCELL_PERM_P2;
    cfg.t_hb_ms = 5;
    cfg.lease_ttl_ms = 1000;
    cfg.announce_ms = 2;
    cfg.announce_retry_max_ms = 5;
    cfg.announce_steady_ms = 20;
    cfg.announce_jitter_ms = 3;
    cfg.discovery_cache_capacity = 2;
    cfg.discovery_cache_ttl_ms = 100;
    cfg.discovery_response_interval_ms = 50;
    cfg.discovery_response_jitter_ms = 10;
    snprintf(cfg.discovery_scope, sizeof(cfg.discovery_scope), "default");
    snprintf(cfg.model, sizeof(cfg.model), "p1-node");
    n = idcell_node_new(&cfg);
    if (with_cap) {
        idcell_capability_t cap;
        fill_cap(&cap);
        idcell_node_register_capability(n, &cap);
    }
    if (capture) {
        idcell_transport_t tr;
        memset(capture, 0, sizeof(*capture));
        memset(&tr, 0, sizeof(tr));
        capture->profile.media = IDCELL_MEDIA_LOOPBACK;
        capture->profile.topology = IDCELL_TOPO_SWITCHED;
        tr.send = capture_send; tr.recv = capture_recv;
        tr.profile = &capture->profile; tr.ctx = capture;
        idcell_node_set_transport(n, &tr);
    }
    return n;
}

static void put8(uint8_t *p, uint16_t *pos, uint8_t type, uint8_t v)
{ idcell_tlv_put(p, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, &v, 1); }
static void put32(uint8_t *p, uint16_t *pos, uint8_t type, uint32_t v)
{ uint8_t b[4]; idcell_put_u32(b, v); idcell_tlv_put(p, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, b, 4); }
static void put64(uint8_t *p, uint16_t *pos, uint8_t type, uint64_t v)
{ uint8_t b[8]; idcell_put_u64(b, v); idcell_tlv_put(p, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, b, 8); }
static void putstr(uint8_t *p, uint16_t *pos, uint8_t type, const char *s)
{ idcell_tlv_put(p, IDCELL_MAX_PAYLOAD, pos, 0, 0, type, s, (uint16_t)strlen(s)); }

static void make_probe_ex(idcell_frame_t *f, const idcell_did_t *src,
                          const idcell_did_t *originator, uint64_t query,
                          const char *scope, uint8_t hop, const char *query_text,
                          const idcell_did_t *target)
{
    uint16_t pos = 0;
    memset(f, 0, sizeof(*f));
    f->ver = IDCELL_PROTO_VER_BYTE; f->type = IDCELL_FT_DISCOVER;
    f->src = *src; memset(&f->dst, 0xFF, 8);
    put8(f->payload, &pos, IDCELL_TLV_MESSAGE, IDCELL_DISCOVER_PROBE);
    put8(f->payload, &pos, IDCELL_TLV_ROLE, IDCELL_ROLE_REQUIREMENT);
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0,
                   IDCELL_TLV_ORIGINATOR, originator->b, 8);
    put64(f->payload, &pos, IDCELL_TLV_QUERY_ID, query);
    putstr(f->payload, &pos, IDCELL_TLV_SCOPE, scope);
    put8(f->payload, &pos, IDCELL_TLV_HOP_LIMIT, hop);
    putstr(f->payload, &pos, IDCELL_TLV_QUERY, query_text ? query_text : "");
    if (target)
        idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0, IDCELL_TLV_TARGET, target->b, 8);
    f->payload_len = pos;
}

static void make_probe(idcell_frame_t *f, const idcell_did_t *src,
                       const idcell_did_t *originator, uint64_t query,
                       const char *scope, uint8_t hop, const char *query_text)
{
    make_probe_ex(f, src, originator, query, scope, hop, query_text, NULL);
}

static void make_checkin(idcell_frame_t *f, const idcell_did_t *src,
                         idcell_wake_profile_t profile, uint32_t checkin,
                         uint32_t latency, int asleep)
{
    uint16_t pos = 0;
    memset(f, 0, sizeof(*f));
    f->ver = IDCELL_PROTO_VER_BYTE; f->type = IDCELL_FT_HEARTBEAT; f->src = *src;
    put8(f->payload, &pos, IDCELL_TLV_CHECKIN,
         asleep ? IDCELL_HEARTBEAT_SLEEP : IDCELL_HEARTBEAT_CHECKIN);
    put8(f->payload, &pos, IDCELL_TLV_WAKE_PROFILE, (uint8_t)profile);
    put32(f->payload, &pos, IDCELL_TLV_CHECKIN_MS, checkin);
    put32(f->payload, &pos, IDCELL_TLV_WAKE_LATENCY, latency);
    put8(f->payload, &pos, IDCELL_TLV_ASLEEP, asleep ? 1 : 0);
    f->payload_len = pos;
}

static void make_valid_hello(idcell_frame_t *f, const idcell_did_t *src,
                             uint8_t message, const idcell_did_t *originator, uint64_t query_id)
{
    idcell_capability_t cap;
    uint8_t inner[IDCELL_MAX_PAYLOAD];
    uint8_t digest[32];
    uint16_t pos = 0, desc_at;
    int len;
    fill_cap(&cap);
    memset(f, 0, sizeof(*f)); f->ver = IDCELL_PROTO_VER_BYTE; f->type = IDCELL_FT_HELLO; f->src = *src;
    put8(f->payload, &pos, IDCELL_TLV_MESSAGE, message);
    put8(f->payload, &pos, IDCELL_TLV_ROLE, IDCELL_ROLE_CAPABILITY);
    putstr(f->payload, &pos, IDCELL_TLV_SUMMARY, "p1-node");
    putstr(f->payload, &pos, IDCELL_TLV_STR, "test-vendor");
    put32(f->payload, &pos, IDCELL_TLV_DESC_VER, 2);
    put32(f->payload, &pos, IDCELL_TLV_U32, 1);
    if (message == IDCELL_DISCOVER_RESPONSE) {
        idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0, IDCELL_TLV_ORIGINATOR,
                       originator->b, 8);
        put64(f->payload, &pos, IDCELL_TLV_QUERY_ID, query_id);
    }
    len = idcell_public_desc_encode(&cap, inner, sizeof(inner));
    desc_at = pos;
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, cap.index, cap.sub,
                   IDCELL_TLV_CAP_DESC, inner, (uint16_t)len);
    idcell_descriptor_digest(1, f->payload + desc_at, pos - desc_at, digest);
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0,
                   IDCELL_TLV_PUBLIC_DIGEST, digest, 32);
    f->payload_len = pos;
}

static void deliver(idcell_node_t *n, const idcell_frame_t *f, uint32_t now)
{
    n->now_ms = now; n->ts_us = (uint64_t)now * 1000ULL;
    node_test_receive_frame(n, f);
}

static int cache_has(const idcell_node_t *n, const idcell_did_t *originator, uint64_t query_id)
{
    int i;
    for (i = 0; i < IDCELL_DISCOVERY_CACHE; i++)
        if (n->discovery_seen[i].used && n->discovery_seen[i].query_id == query_id &&
            idcell_did_equal(&n->discovery_seen[i].originator, originator)) return 1;
    return 0;
}

static const idcell_tlv_t *find_tlv(const idcell_frame_t *f, uint8_t type)
{
    static idcell_tlv_t found;
    idcell_tlv_t t;
    uint16_t pos = 0;
    int rc;
    while ((rc = idcell_tlv_next(f->payload, f->payload_len, &pos, &t)) == 0) {
        if (t.type == type) { found = t; return &found; }
    }
    return NULL;
}

static void test_announce(void)
{
    idcell_node_t *n = make_node(0xA101, 1, NULL);
    idcell_discovery_status_t st;
    idcell_frame_t hello;
    uint32_t first, previous, now = 0, i, max_delay = 0;
    printf("[announce jitter/backoff/steady]\n");
    idcell_node_poll(n, 0);
    idcell_node_discovery_status(n, &st);
    first = st.next_delay_ms;
    dok(first <= 3 && st.announcements == 0 && !st.confirmed, "initial random jitter is bounded and lazy");
    previous = first;
    for (i = 0; i < 9; i++) {
        now += previous;
        idcell_node_poll(n, now);
        idcell_node_discovery_status(n, &st);
        dok(st.next_delay_ms <= 5, "unconfirmed exponential backoff remains capped");
        if (st.next_delay_ms > max_delay) max_delay = st.next_delay_ms;
        previous = st.next_delay_ms;
    }
    dok(max_delay > 2 && st.failures >= 8, "backoff actually progresses and reaches upper bound");
    memset(&hello, 0, sizeof(hello)); hello.ver = IDCELL_PROTO_VER_BYTE;
    hello.type = IDCELL_FT_HELLO; idcell_did_generate(0xA102, &hello.src);
    deliver(n, &hello, now);
    idcell_node_discovery_status(n, &st);
    dok(!st.confirmed, "empty HELLO does not confirm ANNOUNCE");
    make_valid_hello(&hello, &hello.src, IDCELL_DISCOVER_ANNOUNCE, NULL, 0);
    deliver(n, &hello, now);
    idcell_node_discovery_status(n, &st);
    dok(st.confirmed && st.failures == 0 && st.next_delay_ms == 20, "fully valid HELLO confirms and selects fixed steady period");
    now += st.next_delay_ms; idcell_node_poll(n, now);
    idcell_node_discovery_status(n, &st);
    deq((int)st.next_delay_ms, 20, "first confirmed steady interval is fixed");
    now += st.next_delay_ms; idcell_node_poll(n, now);
    idcell_node_discovery_status(n, &st);
    deq((int)st.next_delay_ms, 20, "second confirmed steady interval remains fixed");
    idcell_node_free(n);

    n = make_node(0xA103, 1, NULL);
    idcell_node_poll(n, UINT32_MAX - 2);
    idcell_node_discovery_status(n, &st);
    now = UINT32_MAX - 2 + st.next_delay_ms;
    idcell_node_poll(n, now);
    idcell_node_discovery_status(n, &st);
    deq((int)st.announcements, 1, "announce scheduler fires across u32 wrap");
    dok(st.next_delay_ms <= 5, "wrapped backoff remains bounded");
    idcell_node_free(n);

    {
        idcell_node_t *provider = make_node(0xA104, 1, NULL);
        idcell_node_t *controller = make_node(0xA104, 0, NULL);
        idcell_requirement_t req;
        idcell_discovery_status_t a, b;
        memset(&req, 0, sizeof(req)); req.index = 0xFFFF;
        idcell_node_register_requirement(controller, &req);
        idcell_node_poll(provider, 0); idcell_node_poll(controller, 0);
        idcell_node_discovery_status(provider, &a); idcell_node_discovery_status(controller, &b);
        deq((int)a.next_delay_ms, (int)b.next_delay_ms, "capability and requirement roles share initial ANNOUNCE semantics");
        idcell_node_poll(provider, a.next_delay_ms); idcell_node_poll(controller, a.next_delay_ms);
        idcell_node_discovery_status(provider, &a); idcell_node_discovery_status(controller, &b);
        deq((int)a.next_delay_ms, (int)b.next_delay_ms, "capability and requirement roles share backoff semantics");
        idcell_node_free(provider); idcell_node_free(controller);
    }
}

static void test_probe_wire_and_scope(void)
{
    capture_t ac, bc;
    idcell_node_t *a = make_node(0xB001, 0, &ac);
    idcell_node_t *b = make_node(0xB002, 1, &bc);
    idcell_probe_t probe;
    idcell_frame_t f, response;
    const idcell_tlv_t *t;
    idcell_discovery_status_t st;
    memset(&probe, 0, sizeof(probe));
    probe.query_id = 42; probe.scope = "default"; probe.hop_limit = 2; probe.query = "temperature";
    deq(idcell_node_probe(a, &probe), IDCELL_OK, "real active PROBE API sends on transport");
    deq(capture_type(&ac, IDCELL_FT_DISCOVER, 0, &f), 0, "PROBE uses existing DISCOVER TYPE");
    t = find_tlv(&f, IDCELL_TLV_MESSAGE); dok(t && t->val[0] == IDCELL_DISCOVER_PROBE, "PROBE has explicit message TLV");
    t = find_tlv(&f, IDCELL_TLV_ROLE); dok(t && t->val[0] != 0, "PROBE has explicit role TLV");
    t = find_tlv(&f, IDCELL_TLV_ORIGINATOR); dok(t && t->len == 8 && memcmp(t->val, a->cfg.did.b, 8) == 0, "PROBE carries originator_id");
    t = find_tlv(&f, IDCELL_TLV_QUERY_ID); dok(t && idcell_get_u64(t->val) == 42, "PROBE carries query_id");
    t = find_tlv(&f, IDCELL_TLV_HOP_LIMIT); dok(t && t->val[0] == 2, "PROBE carries hop_limit");
    t = find_tlv(&f, IDCELL_TLV_QUERY); dok(t && t->len == 11 && memcmp(t->val, "temperature", 11) == 0, "PROBE carries opaque query");

    deliver(b, &f, 100);
    idcell_node_discovery_status(b, &st);
    deq(st.last_probe_err, IDCELL_OK, "in-scope PROBE accepted");
    deq((int)st.descriptor_fetches, 1, "in-scope PROBE loads descriptor once");
    deq(capture_count_type(&bc, IDCELL_FT_DISCOVER), 1, "positive hop PROBE forwards once");
    capture_type(&bc, IDCELL_FT_DISCOVER, 0, &f);
    t = find_tlv(&f, IDCELL_TLV_HOP_LIMIT); dok(t && t->val[0] == 1, "forward decrements hop_limit");
    deq(capture_count_type(&bc, IDCELL_FT_HELLO), 0, "response is delayed rather than immediate");
    bc.now = b->discovery_responses[0].due_ms;
    idcell_node_poll(b, bc.now);
    deq(capture_type(&bc, IDCELL_FT_HELLO, 0, &response), 0, "scheduled HELLO response is sent");
    t = find_tlv(&response, IDCELL_TLV_MESSAGE); dok(t && t->val[0] == IDCELL_DISCOVER_RESPONSE, "HELLO marks PROBE response");
    t = find_tlv(&response, IDCELL_TLV_QUERY_ID); dok(t && idcell_get_u64(t->val) == 42, "response correlates query_id");

    capture_clear(&bc);
    make_probe(&f, &a->cfg.did, &a->cfg.did, 43, "other", 3, "temperature");
    deliver(b, &f, 200);
    idcell_node_discovery_status(b, &st);
    deq(st.last_probe_err, IDCELL_E_SCOPE, "outside scope returns concrete scope state");
    deq((int)st.descriptor_fetches, 1, "outside scope does not fetch descriptor");
    deq(bc.count, 0, "outside scope neither forwards nor responds");

    make_probe(&f, &a->cfg.did, &a->cfg.did, 44, "default", 0, "temperature");
    deliver(b, &f, 201);
    deq(capture_count_type(&bc, IDCELL_FT_DISCOVER), 0, "hop zero never forwards");
    idcell_node_free(a); idcell_node_free(b);
}

static void test_dedup_ttl_lru_recovery(void)
{
    capture_t c;
    idcell_node_t *n = make_node(0xB101, 1, &c);
    idcell_did_t origin, relay2;
    idcell_frame_t f;
    idcell_discovery_status_t st;
    idcell_did_generate(0xB110, &origin); idcell_did_generate(0xB111, &relay2);
    printf("[probe dedup TTL/LRU/recovery]\n");
    make_probe(&f, &origin, &origin, 1, "default", 2, "temperature"); deliver(n, &f, 0);
    make_probe(&f, &relay2, &origin, 1, "default", 1, "temperature"); deliver(n, &f, 1);
    idcell_node_discovery_status(n, &st);
    deq(st.last_probe_err, IDCELL_E_DUPLICATE, "dual-path duplicate has explicit duplicate state");
    deq((int)st.descriptor_fetches, 1, "dual-path duplicate processes descriptor only once");

    make_probe(&f, &origin, &origin, 2, "default", 0, ""); deliver(n, &f, 2);
    make_probe(&f, &origin, &origin, 1, "default", 0, ""); deliver(n, &f, 3); /* refresh LRU */
    make_probe(&f, &origin, &origin, 3, "default", 0, ""); deliver(n, &f, 4);
    idcell_node_discovery_status(n, &st); deq((int)st.cache_size, 2, "dedup cache honors configured capacity");
    make_probe(&f, &origin, &origin, 2, "default", 0, ""); deliver(n, &f, 5);
    idcell_node_discovery_status(n, &st);
    deq(st.last_probe_err, IDCELL_OK, "least recently used entry was evicted and can be retried");
    idcell_node_free(n);

    n = make_node(0xB102, 1, &c); n->cfg.discovery_cache_ttl_ms = 5;
    make_probe(&f, &origin, &origin, 8, "default", 0, ""); deliver(n, &f, 0);
    make_probe(&f, &origin, &origin, 8, "default", 0, ""); deliver(n, &f, 4);
    idcell_node_discovery_status(n, &st); deq(st.last_probe_err, IDCELL_E_DUPLICATE, "dedup entry remains before TTL");
    make_probe(&f, &origin, &origin, 8, "default", 0, ""); deliver(n, &f, 5);
    idcell_node_discovery_status(n, &st); deq(st.last_probe_err, IDCELL_OK, "TTL expiry permits retry at exact deadline");
    idcell_node_free(n);

    n = make_node(0xB103, 0, &c);
    make_probe(&f, &origin, &origin, 9, "default", 2, ""); deliver(n, &f, 0);
    idcell_node_discovery_status(n, &st);
    deq(st.last_probe_err, IDCELL_E_UNAVAILABLE, "temporarily unavailable descriptor reports local failure");
    deq((int)st.cache_size, 1, "forwarded probe retains dedup while local response is pending");
    deq(capture_count_type(&c, IDCELL_FT_DISCOVER), 1, "descriptor unavailable does not block relay forwarding");
    { idcell_capability_t cap; fill_cap(&cap); idcell_node_register_capability(n, &cap); }
    deliver(n, &f, 1);
    idcell_node_discovery_status(n, &st);
    deq(st.last_probe_err, IDCELL_OK, "same query recovers after descriptor becomes available");
    deq((int)st.descriptor_fetches, 1, "recovery performs one real descriptor fetch");
    idcell_node_free(n);
}

static void test_response_pacing(void)
{
    capture_t c1, c2;
    idcell_node_t *a = make_node(0xB201, 1, &c1);
    idcell_node_t *b = make_node(0xB201, 1, &c2);
    idcell_did_t origin;
    idcell_frame_t f;
    uint32_t due_a, due_b, first_at;
    int sent;
    idcell_did_generate(0xB202, &origin);
    printf("[seeded response pacing]\n");
    make_probe(&f, &origin, &origin, 1, "default", 0, ""); deliver(a, &f, 0); deliver(b, &f, 0);
    make_probe(&f, &origin, &origin, 2, "default", 0, ""); deliver(a, &f, 0); deliver(b, &f, 0);
    due_a = a->discovery_responses[0].due_ms; due_b = b->discovery_responses[0].due_ms;
    deq((int)due_a, (int)due_b, "same fixed seed yields reproducible response jitter");
    dok(a->discovery_responses[1].due_ms - due_a >= 50, "second scheduled response honors actual-time interval");
    c1.now = 1000; idcell_node_poll(a, 1000); sent = capture_count_type(&c1, IDCELL_FT_HELLO);
    deq(sent, 1, "late poll sends only one due response");
    first_at = c1.at[c1.count - 1];
    c1.now = 1000; idcell_node_poll(a, 1000);
    deq(capture_count_type(&c1, IDCELL_FT_HELLO), sent, "late poll cannot bunch responses at same actual time");
    c1.now = first_at + 49; idcell_node_poll(a, c1.now);
    deq(capture_count_type(&c1, IDCELL_FT_HELLO), sent, "actual response interval excludes early send");
    c1.now = first_at + 50; idcell_node_poll(a, c1.now);
    deq(capture_count_type(&c1, IDCELL_FT_HELLO), sent + 1, "next response sends at actual interval deadline");
    idcell_node_free(a); idcell_node_free(b);
}

static void test_relay_filter_and_send_fault(void)
{
    capture_t c;
    idcell_node_t *n;
    idcell_did_t origin, target;
    idcell_frame_t f, out;
    idcell_discovery_status_t st;
    idcell_probe_t probe;
    const idcell_tlv_t *t;
    int i;
    printf("[relay/filter/send-fault]\n");
    idcell_did_generate(0xB301, &origin); idcell_did_generate(0xB302, &target);
    n = make_node(0xB300, 0, &c);
    idcell_node_poll(n, 0); idcell_node_discovery_status(n, &st);
    c.now = st.next_delay_ms; idcell_node_poll(n, c.now);
    deq(capture_count_type(&c, IDCELL_FT_DISCOVER), 1, "pure relay without cap/req still ANNOUNCEs");
    capture_clear(&c);
    make_probe_ex(&f, &origin, &origin, 30, "default", 2, "temperature", &target);
    f.dst = target; deliver(n, &f, 1);
    deq(capture_type(&c, IDCELL_FT_DISCOVER, 0, &out), 0, "pure relay forwards without local descriptor");
    dok(idcell_did_equal(&out.src, &origin) && idcell_did_equal(&out.dst, &target),
        "relay preserves end-to-end SRC/DST instead of relay DID");
    deq((int)out.seq, (int)f.seq, "relay preserves end-to-end sequence field");
    t = find_tlv(&out, IDCELL_TLV_HOP_LIMIT); dok(t && t->val[0] == 1, "relay changes only hop_limit to one");
    deq(capture_count_type(&c, IDCELL_FT_HELLO), 0, "pure relay emits no local HELLO");
    idcell_node_discovery_status(n, &st); deq((int)st.descriptor_fetches, 0, "pure relay never reads a descriptor");

    make_probe(&f, &origin, &origin, 31, "default", 1, ""); c.fail_send = 1; deliver(n, &f, 2);
    idcell_node_discovery_status(n, &st);
    deq(st.last_probe_err, IDCELL_E_UNSAFE, "forward send fault propagates real transport error");
    deq((int)st.cache_size, 1, "failed forward leaves no terminal dedup for new query");
    deliver(n, &f, 3); idcell_node_discovery_status(n, &st);
    deq(st.last_probe_err, IDCELL_E_UNAVAILABLE, "same query retries after forward fault");
    deq(capture_count_type(&c, IDCELL_FT_DISCOVER), 2, "retry really forwards after one send fault");
    idcell_node_free(n);

    n = make_node(0xB303, 1, &c);
    make_probe_ex(&f, &origin, &origin, 32, "default", 1, "temperature", &target);
    deliver(n, &f, 0); idcell_node_discovery_status(n, &st);
    deq((int)st.descriptor_fetches, 0, "target other DID does not read local descriptor");
    deq(capture_count_type(&c, IDCELL_FT_DISCOVER), 1, "target other DID still forwards");
    deq(capture_count_type(&c, IDCELL_FT_HELLO), 0, "target other DID suppresses local HELLO");
    make_probe(&f, &origin, &origin, 33, "default", 0, "nonexistent"); deliver(n, &f, 1);
    idcell_node_discovery_status(n, &st);
    deq((int)st.descriptor_fetches, 0, "nonexistent query performs no descriptor read");
    deq(capture_count_type(&c, IDCELL_FT_HELLO), 0, "nonexistent query has no local response");
    memset(&probe, 0, sizeof(probe)); probe.query_id = 34; probe.query = "temperature";
    c.fail_send = 1;
    deq(idcell_node_probe(n, &probe), IDCELL_E_UNSAFE, "active PROBE propagates send fault");
    deq(idcell_node_probe(n, &probe), IDCELL_OK, "active PROBE succeeds after transient send fault");
    idcell_node_free(n);

    n = make_node(0xB304, 1, &c);
    make_probe(&f, &origin, &origin, 35, "default", 0, "temperature"); deliver(n, &f, 0);
    c.fail_send = 1; c.now = n->discovery_responses[0].due_ms; idcell_node_poll(n, c.now);
    deq(capture_count_type(&c, IDCELL_FT_HELLO), 0, "async HELLO send fault emits no frame");
    dok(n->discovery_responses[0].used && n->discovery_responses[0].attempts == 1,
        "async response retains bounded retry state");
    c.now = n->discovery_responses[0].due_ms; idcell_node_poll(n, c.now);
    deq(capture_count_type(&c, IDCELL_FT_HELLO), 1, "async response retries successfully after one fault");
    make_probe(&f, &origin, &origin, 36, "default", 0, "temperature"); deliver(n, &f, 100);
    c.fail_send = 10;
    for (i = 0; i < 4; i++) { c.now = n->discovery_responses[0].due_ms; idcell_node_poll(n, c.now); }
    idcell_node_discovery_status(n, &st);
    dok(!cache_has(n, &origin, 36), "final send abandonment removes failed query dedup");
    c.fail_send = 0; deliver(n, &f, 101); idcell_node_discovery_status(n, &st);
    deq(st.last_probe_err, IDCELL_OK, "abandoned query recovers within original TTL");
    idcell_node_free(n);
}

static void test_hello_response_correlation(void)
{
    capture_t c;
    idcell_node_t *n = make_node(0xB401, 1, &c);
    idcell_did_t peer;
    idcell_frame_t f;
    idcell_probe_t probe;
    idcell_discovery_status_t st;
    printf("[hello-response-correlation]\n");
    idcell_did_generate(0xB402, &peer);
    memset(&probe, 0, sizeof(probe)); probe.query_id = 55; probe.query = "temperature";
    deq(idcell_node_probe(n, &probe), IDCELL_OK, "pending probe established by real send");
    make_valid_hello(&f, &peer, IDCELL_DISCOVER_RESPONSE, &n->cfg.did, 54); deliver(n, &f, 1);
    idcell_node_discovery_status(n, &st); dok(!st.confirmed, "wrong query_id response does not confirm ANNOUNCE");
    make_valid_hello(&f, &peer, IDCELL_DISCOVER_RESPONSE, &peer, 55); deliver(n, &f, 2);
    idcell_node_discovery_status(n, &st); dok(!st.confirmed, "wrong originator response does not confirm ANNOUNCE");
    make_valid_hello(&f, &peer, IDCELL_DISCOVER_RESPONSE, &n->cfg.did, 55); deliver(n, &f, 3);
    idcell_node_discovery_status(n, &st);
    dok(st.confirmed, "matching originator/query response is accepted");
    deq(idcell_node_peer_cap_count(n, &peer), 1, "validated response commits complete public descriptor");
    idcell_node_free(n);
}

static void test_wake_profiles_and_presence(void)
{
    capture_t c;
    idcell_node_t *n;
    idcell_frame_t f;
    idcell_did_t peer;
    idcell_probe_t probe;
    idcell_did_generate(0xC102, &peer);
    memset(&probe, 0, sizeof(probe)); probe.query_id = 1;
    printf("[wake profiles and presence]\n");
    n = make_node(0xC100, 1, &c);
    deq(idcell_node_sleep(n, 0), IDCELL_E_STATE, "ALWAYS_ON rejects sleep transition");
    idcell_node_free(n);

    n = make_node(0xC100, 1, &c); n->cfg.wake_profile = IDCELL_WAKE_SCHEDULED;
    n->cfg.wake_after_ms = 20; n->cfg.checkin_ms = 20; n->cfg.max_wake_latency_ms = 30;
    deq(idcell_node_sleep(n, 0), IDCELL_OK, "SCHEDULED enters real asleep state");
    make_valid_hello(&f, &peer, IDCELL_DISCOVER_ANNOUNCE, NULL, 0); deliver(n, &f, 18);
    dok(idcell_node_asleep(n), "SCHEDULED valid HELLO is not a timer wake event");
    idcell_node_poll(n, 19); dok(idcell_node_asleep(n), "SCHEDULED remains asleep before deadline");
    c.now = 20; idcell_node_poll(n, 20); dok(!idcell_node_asleep(n), "SCHEDULED wakes automatically at deadline");
    deq(capture_type(&c, IDCELL_FT_HEARTBEAT, 1, &f), 0, "automatic wake emits online CHECK-IN");
    { const idcell_tlv_t *t = find_tlv(&f, IDCELL_TLV_CHECKIN); dok(t && t->val[0] == IDCELL_HEARTBEAT_CHECKIN, "HEARTBEAT carries explicit CHECK-IN subtype"); }
    idcell_node_free(n);

    n = make_node(0xC100, 1, &c); n->cfg.wake_profile = IDCELL_WAKE_RADIO; n->cfg.wake_budget = 1;
    idcell_node_sleep(n, 0);
    deq(idcell_node_wake(n, IDCELL_WAKE_EVENT_PROXY, 1), IDCELL_E_STATE, "WAKE_RADIO rejects proxy-only event");
    memset(&f, 0, sizeof(f)); f.ver = IDCELL_PROTO_VER_BYTE; f.type = IDCELL_FT_HELLO; f.src = peer;
    deliver(n, &f, 2); dok(idcell_node_asleep(n), "empty HELLO cannot wake RADIO profile");
    make_valid_hello(&f, &peer, IDCELL_DISCOVER_ANNOUNCE, NULL, 0); deliver(n, &f, 3);
    dok(idcell_node_asleep(n), "valid frame alone is not authorized RADIO event");
    deq(idcell_node_wake(n, IDCELL_WAKE_EVENT_RADIO, 4), IDCELL_OK, "explicit transport RADIO event wakes node");
    idcell_node_sleep(n, 5);
    deq(idcell_node_wake(n, IDCELL_WAKE_EVENT_RADIO, 6), IDCELL_E_STATE, "repeated RADIO event exceeds independent wake budget");
    dok(idcell_node_asleep(n), "budget rejection leaves node asleep");
    deq(idcell_node_wake(n, IDCELL_WAKE_EVENT_LOCAL, 7), IDCELL_OK, "LOCAL remains explicit local-only wake path");
    idcell_node_free(n);

    n = make_node(0xC100, 1, &c); n->cfg.wake_profile = IDCELL_WAKE_PROXY;
    idcell_node_sleep(n, 0); deliver(n, &f, 2);
    dok(idcell_node_asleep(n), "WAKE_PROXY is not implicitly woken by direct frame");
    deq(idcell_node_wake(n, IDCELL_WAKE_EVENT_PROXY, 3), IDCELL_OK, "WAKE_PROXY accepts explicit proxy event");
    idcell_node_free(n);

    n = make_node(0xC100, 1, &c); n->cfg.wake_profile = IDCELL_WAKE_RX_OFF;
    idcell_node_sleep(n, 0);
    deq(idcell_node_probe(n, &probe), IDCELL_E_RX_OFF, "RX_OFF rejects protocol PROBE without implicit wake");
    deq(idcell_node_check_in(n, 1), IDCELL_E_RX_OFF, "RX_OFF rejects CHECK-IN while off");
    deliver(n, &f, 2);
    dok(idcell_node_asleep(n) && idcell_node_last_error(n) == IDCELL_E_RX_OFF, "remote frame cannot wake RX_OFF");
    deq(idcell_node_poll(n, 3), IDCELL_E_RX_OFF, "RX_OFF poll returns concrete error");
    deq(idcell_node_wake(n, IDCELL_WAKE_EVENT_RADIO, 4), IDCELL_E_RX_OFF, "remote radio event is not valid RX_OFF wake");
    deq(idcell_node_wake(n, IDCELL_WAKE_EVENT_LOCAL, 5), IDCELL_OK, "explicit local event wakes RX_OFF");
    idcell_node_free(n);

    n = make_node(0xC101, 0, &c);
    make_checkin(&f, &peer, IDCELL_WAKE_ALWAYS_ON, 0, 0, 0); deliver(n, &f, 0);
    deq(idcell_node_peer_presence(n, &peer, 14), IDCELL_PRESENCE_ONLINE, "ordinary heartbeat presence online before three heartbeats");
    deq(idcell_node_peer_presence(n, &peer, 15), IDCELL_PRESENCE_OFFLINE, "ordinary peer offline at three heartbeats");
    make_checkin(&f, &peer, IDCELL_WAKE_SCHEDULED, 20, 30, 1); deliver(n, &f, 20);
    deq(idcell_node_peer_presence(n, &peer, 49), IDCELL_PRESENCE_ASLEEP, "scheduled asleep is distinct from offline");
    deq(idcell_node_peer_presence(n, &peer, 50), IDCELL_PRESENCE_OFFLINE, "scheduled peer offline at maximum wake upper bound");
    make_checkin(&f, &peer, IDCELL_WAKE_SCHEDULED, 20, 30, 0); deliver(n, &f, 51);
    deq(idcell_node_peer_presence(n, &peer, 80), IDCELL_PRESENCE_ONLINE, "valid CHECK-IN restores online reachability");
    deq(idcell_node_peer_presence(n, &peer, 81), IDCELL_PRESENCE_OFFLINE, "restored scheduled presence expires at new upper bound");
    make_checkin(&f, &peer, IDCELL_WAKE_ALWAYS_ON, 0, 0, 0); deliver(n, &f, 82);
    memset(&f, 0, sizeof(f)); f.ver = IDCELL_PROTO_VER_BYTE; f.type = IDCELL_FT_OFFLINE; f.src = peer;
    deliver(n, &f, 83);
    deq(idcell_node_peer_presence(n, &peer, 84), IDCELL_PRESENCE_OFFLINE, "explicit FT_OFFLINE forces persistent offline");
    dok(n->peers[0].suspended && !n->peers[0].owner_token, "FT_OFFLINE suspends and revokes running context");
    f.type = IDCELL_FT_DISCOVER; deliver(n, &f, 85);
    deq(idcell_node_peer_presence(n, &peer, 86), IDCELL_PRESENCE_OFFLINE, "ordinary decodable frame cannot clear OFFLINE");
    f.type = IDCELL_FT_HELLO; deliver(n, &f, 87);
    deq(idcell_node_peer_presence(n, &peer, 88), IDCELL_PRESENCE_OFFLINE, "empty HELLO cannot clear OFFLINE");
    make_checkin(&f, &peer, IDCELL_WAKE_ALWAYS_ON, 0, 0, 0); deliver(n, &f, 89);
    deq(idcell_node_peer_presence(n, &peer, 89), IDCELL_PRESENCE_ONLINE, "new valid CHECK-IN resumes from OFFLINE");
    f.type = IDCELL_FT_OFFLINE; f.payload_len = 0; deliver(n, &f, 90);
    make_valid_hello(&f, &peer, IDCELL_DISCOVER_ANNOUNCE, NULL, 0); deliver(n, &f, 91);
    deq(idcell_node_peer_presence(n, &peer, 91), IDCELL_PRESENCE_ONLINE, "new fully valid HELLO resumes from OFFLINE");
    idcell_node_free(n);
}

/* 真实两端绑定场景，mailbox 仍走 P0-3 的同一 WRITE 执行器。 */
typedef struct { int set_calls; double value; } dev_state_t;
static int setter(void *ud, uint16_t index, uint8_t sub, double value,
                  const char *intent, uint32_t owner)
{
    dev_state_t *s = (dev_state_t *)ud;
    (void)index; (void)sub; (void)intent; (void)owner;
    s->set_calls++; s->value = value; return IDCELL_OK;
}
typedef struct {
    idcell_loopback_t *lb;
    idcell_node_t *dev, *host;
    idcell_did_t dev_did, host_did;
    dev_state_t state;
    uint32_t now;
    int write_results, last_write_err;
} scene_t;
static void write_result(void *ud, const idcell_did_t *peer, uint16_t index, uint8_t sub,
                         const idcell_write_result_t *res)
{
    scene_t *s = (scene_t *)ud;
    (void)peer; (void)index; (void)sub;
    s->write_results++; s->last_write_err = res->err;
}
static void scene_init(scene_t *s)
{
    idcell_transport_t a, b;
    idcell_node_cfg_t cfg;
    idcell_capability_t cap;
    idcell_requirement_t req;
    memset(s, 0, sizeof(*s));
    s->lb = idcell_loopback_new(); idcell_loopback_endpoints(s->lb, &a, &b);
    memset(&cfg, 0, sizeof(cfg)); idcell_did_generate(0xD001, &cfg.did);
    memset(cfg.cred, 0x42, sizeof(cfg.cred)); cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 20; cfg.announce_jitter_ms = 1; cfg.announce_retry_max_ms = 40;
    cfg.discovery_response_interval_ms = 1; cfg.discovery_response_jitter_ms = 1;
    cfg.lease_ttl_ms = 1000; snprintf(cfg.model, sizeof(cfg.model), "sleep-dev");
    s->dev = idcell_node_new(&cfg); idcell_node_set_transport(s->dev, &a);
    fill_cap(&cap); idcell_node_register_capability(s->dev, &cap);
    idcell_node_set_setter(s->dev, setter, &s->state);
    memset(&cfg, 0, sizeof(cfg)); idcell_did_generate(0xD002, &cfg.did);
    memset(cfg.cred, 0x42, sizeof(cfg.cred)); cfg.max_perm = IDCELL_PERM_P2;
    cfg.announce_ms = 20; cfg.announce_jitter_ms = 1; cfg.announce_retry_max_ms = 40;
    cfg.discovery_response_interval_ms = 1; cfg.discovery_response_jitter_ms = 1;
    cfg.lease_ttl_ms = 1000; snprintf(cfg.model, sizeof(cfg.model), "sleep-host");
    s->host = idcell_node_new(&cfg); idcell_node_set_transport(s->host, &b);
    idcell_node_set_write_result_sink(s->host, write_result, s);
    memset(&req, 0, sizeof(req)); req.index = 0xFFFF; req.kind = IDCELL_KIND_STATE;
    req.qty = IDCELL_QTY_TEMPERATURE; req.perm = IDCELL_PERM_P2;
    snprintf(req.unit, sizeof(req.unit), "Cel"); req.accept_count = 1;
    snprintf(req.accept_units[0], sizeof(req.accept_units[0]), "Cel");
    req.want_ms = 20; req.stale_ms = 1000;
    idcell_type_list_add(req.accept_types, &req.accept_type_count, IDCELL_DTYPE_F64, 0);
    idcell_node_register_requirement(s->host, &req);
    s->dev_did = idcell_node_did(s->dev); s->host_did = idcell_node_did(s->host);
}
static void scene_free(scene_t *s)
{ idcell_node_free(s->dev); idcell_node_free(s->host); idcell_loopback_free(s->lb); }
static void scene_step(scene_t *s)
{ idcell_node_poll(s->dev, s->now); idcell_node_poll(s->host, s->now); s->now += 10; }
static int scene_bind(scene_t *s)
{
    int i; idcell_contract_t c;
    for (i = 0; i < 500; i++) {
        scene_step(s);
        if (idcell_node_get_contract(s->host, &s->dev_did, &c) == IDCELL_OK &&
            idcell_node_get_contract(s->dev, &s->host_did, &c) == IDCELL_OK) return 1;
    }
    return 0;
}
static int scene_reactivate(scene_t *s, uint64_t old_session)
{
    int i;
    idcell_contract_t a, b;
    for (i = 0; i < 500; i++) {
        scene_step(s);
        if (idcell_node_get_contract(s->dev, &s->host_did, &a) == IDCELL_OK &&
            idcell_node_get_contract(s->host, &s->dev_did, &b) == IDCELL_OK &&
            !s->dev->peers[0].recovery && !s->host->peers[0].recovery &&
            !s->dev->peers[0].suspended && !s->host->peers[0].suspended &&
            a.session_id == b.session_id && a.session_id != old_session) return 1;
    }
    return 0;
}
static idcell_contract_point_t *contract_point_test(idcell_contract_t *c, uint16_t index)
{
    int i;
    for (i = 0; i < c->pt_count; i++) if (c->pt[i].index == index) return &c->pt[i];
    return NULL;
}
static void make_write(scene_t *s, idcell_frame_t *f, double value, uint64_t command, uint32_t valid)
{
    idcell_contract_t c;
    idcell_contract_point_t *cp;
    uint16_t pos = 0; uint8_t b[8];
    idcell_node_get_contract(s->host, &s->dev_did, &c); cp = contract_point_test(&c, 0x0200);
    memset(f, 0, sizeof(*f)); f->ver = IDCELL_PROTO_VER_BYTE; f->type = IDCELL_FT_WRITE;
    f->src = s->host_did; f->dst = s->dev_did; f->txn = (uint16_t)command;
    idcell_put_f64(b, value);
    idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0x0200, 0, IDCELL_TLV_VALUE, b, 8);
    { uint8_t x[2]; idcell_put_u16(x, cp ? cp->schema_ref : 1);
      idcell_tlv_put(f->payload, sizeof(f->payload), &pos, 0, 0, IDCELL_TLV_SCHEMA_REF, x, 2); }
    put32(f->payload, &pos, IDCELL_TLV_BIND_ID, c.binding_id);
    put64(f->payload, &pos, IDCELL_TLV_SESSION_ID, c.session_id);
    put64(f->payload, &pos, IDCELL_TLV_GRANT_EPOCH, c.grant_epoch);
    put64(f->payload, &pos, IDCELL_TLV_AUTHORITY_ID, c.authority_id);
    put64(f->payload, &pos, IDCELL_TLV_AUTHORITY_EPOCH, c.authority_epoch);
    put64(f->payload, &pos, IDCELL_TLV_MEMBER_EPOCH, c.member_epoch);
    put64(f->payload, &pos, IDCELL_TLV_COMMAND_ID, command);
    put32(f->payload, &pos, IDCELL_TLV_VALID_FOR, valid);
    put32(f->payload, &pos, IDCELL_TLV_OWNER, c.owner_token);
    putstr(f->payload, &pos, IDCELL_TLV_INTENT, "sleep-mailbox");
    f->payload_len = pos;
}
static int patch_field(idcell_frame_t *f, uint8_t type, uint64_t value)
{
    uint16_t pos = 0;
    while (pos + 6 <= f->payload_len) {
        uint16_t len = idcell_get_u16(f->payload + pos + 4);
        if (pos + 6 + len > f->payload_len) return 0;
        if (f->payload[pos + 3] == type) {
            if (len == 4) idcell_put_u32(f->payload + pos + 6, (uint32_t)value);
            else if (len == 8) idcell_put_u64(f->payload + pos + 6, value);
            else return 0;
            return 1;
        }
        pos = (uint16_t)(pos + 6 + len);
    }
    return 0;
}
static void prepare_sleep(scene_t *s)
{
    s->dev->cfg.wake_profile = IDCELL_WAKE_PROXY;
    idcell_node_sleep(s->dev, s->now);
}
static int deliver_write_result(scene_t *s, idcell_frame_t *f, double value, uint64_t command)
{
    idcell_peer_t *p = &s->host->peers[0];
    int before = s->write_results;
    p->write_pending = 1; p->write_txn = f->txn; p->write_index = 0x0200; p->write_sub = 0;
    p->write_value = value; p->write_command_id = command;
    p->write_binding = p->contract.binding_id; p->write_session = p->contract.session_id;
    p->write_grant = p->contract.grant_epoch; p->write_authority = p->contract.authority_id;
    p->write_authority_epoch = p->contract.authority_epoch; p->write_member_epoch = p->contract.member_epoch;
    node_test_handle_frame(s->dev, f); idcell_node_poll(s->host, s->now);
    return s->write_results > before ? s->last_write_err : -1;
}

static void test_sleep_mailbox(void)
{
    scene_t s;
    idcell_frame_t w, x;
    idcell_contract_t before, after;
    uint64_t old_session, old_grant;
    int base;
    printf("[suspended mailbox and new-context activation]\n");
    scene_init(&s); dok(scene_bind(&s), "bind real producer/consumer before sleep");
    idcell_node_get_contract(s.dev, &s.host_did, &before);
    old_session = before.session_id; old_grant = before.grant_epoch;
    prepare_sleep(&s); base = s.state.set_calls;
    dok(s.dev->peers[0].suspended, "entering sleep immediately marks peer contract suspended");
    dok(idcell_node_bind_phase(s.dev, &s.host_did) != IDCELL_BIND_ACTIVE, "suspended contract is not externally active");
    make_write(&s, &w, 24, 1, 500); node_test_receive_frame(s.dev, &w);
    deq(idcell_node_mailbox_count(s.dev), 1, "valid write enters bounded sleep mailbox");
    deq(s.state.set_calls, base, "suspended mailbox has no setter side effect");
    idcell_node_poll(s.dev, s.now + 10); deq(s.state.set_calls, base, "suspended poll cannot execute or renew active lease");
    idcell_node_wake(s.dev, IDCELL_WAKE_EVENT_PROXY, s.now + 20);
    dok(s.dev->peers[0].recovery, "every wake forces recovery even when old TTL is still valid");
    idcell_node_poll(s.dev, s.now + 20);
    deq(s.state.set_calls, base, "old FIFO cannot execute before new session/grant activation");
    deq(idcell_node_mailbox_count(s.dev), 1, "recovery retains FIFO without executing it");
    dok(scene_reactivate(&s, old_session), "wake recovery activates a genuinely new session/grant");
    idcell_node_get_contract(s.dev, &s.host_did, &after);
    dok(after.session_id != old_session && after.grant_epoch > old_grant, "new activation changes session and raises grant epoch");
    idcell_node_poll(s.dev, s.now + 1);
    deq(s.state.set_calls, base, "old-session FIFO remains forbidden after new activation");
    node_test_handle_frame(s.dev, &w);
    deq(s.state.set_calls, base, "replayed old-context command has no side effect after recovery");
    make_write(&s, &w, 24, 2, 500);
    node_test_handle_frame(s.dev, &w); node_test_handle_frame(s.dev, &w);
    deq(s.state.set_calls, base + 1, "new-context write executes once and duplicate stays idempotent");
    x = w; patch_field(&x, IDCELL_TLV_GRANT_EPOCH, old_grant);
    node_test_handle_frame(s.dev, &x);
    deq(s.state.set_calls, base + 1, "old grant epoch is fenced under new session");
    scene_free(&s);

    scene_init(&s); scene_bind(&s); prepare_sleep(&s); base = s.state.set_calls;
    make_write(&s, &w, 25, 3, 5); node_test_receive_frame(s.dev, &w);
    idcell_node_poll(s.dev, s.now + 6);
    idcell_node_wake(s.dev, IDCELL_WAKE_EVENT_PROXY, s.now + 6); idcell_node_poll(s.dev, s.now + 6);
    deq(s.state.set_calls, base, "positive TTL expiry never catches up execution");
    scene_free(&s);

    scene_init(&s); scene_bind(&s); prepare_sleep(&s); base = s.state.set_calls;
    make_write(&s, &w, NAN, 4, 500); node_test_receive_frame(s.dev, &w);
    deq(idcell_node_mailbox_count(s.dev), 0, "NaN is rejected before sleep FIFO admission");
    make_write(&s, &w, INFINITY, 5, 500); node_test_receive_frame(s.dev, &w);
    deq(idcell_node_mailbox_count(s.dev), 0, "Inf is rejected before sleep FIFO admission");
    idcell_node_wake(s.dev, IDCELL_WAKE_EVENT_PROXY, s.now + 1);
    node_test_handle_frame(s.dev, &w);
    deq(s.state.set_calls, base, "NaN/Inf never reach setter even at execution boundary");
    deq(idcell_node_write(s.host, 0x0200, 0, NAN, 1, "nan"), IDCELL_E_RANGE,
        "local write API also rejects NaN with E_RANGE");
    scene_free(&s);

    scene_init(&s); scene_bind(&s); prepare_sleep(&s); base = s.state.set_calls;
    {
        int i;
        for (i = 0; i < IDCELL_WRITE_QUEUE; i++) {
            make_write(&s, &w, 20 + i, (uint64_t)(100 + i), 500);
            node_test_receive_frame(s.dev, &w);
        }
        deq(idcell_node_mailbox_count(s.dev), IDCELL_WRITE_QUEUE, "sleep mailbox reaches exact bounded capacity");
        make_write(&s, &w, 40, 999, 500); node_test_receive_frame(s.dev, &w);
        deq(idcell_node_mailbox_count(s.dev), IDCELL_WRITE_QUEUE, "overflow is rejected without growing mailbox");
        deq(s.state.set_calls, base, "full suspended mailbox still has no side effects");
    }
    scene_free(&s);
}

static void run_tests(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_announce();
    test_probe_wire_and_scope();
    test_dedup_ttl_lru_recovery();
    test_response_pacing();
    test_relay_filter_and_send_fault();
    test_hello_response_correlation();
    test_wake_profiles_and_presence();
    test_sleep_mailbox();
    printf("SUMMARY pass=%d fail=%d\n", d_pass, d_fail);
}

static int vector_announce(void)
{
    idcell_node_t *n = make_node(0xA101, 1, NULL);
    idcell_discovery_status_t st;
    idcell_frame_t hello;
    uint32_t now = 0, delay, max_delay = 0, first, steady1, steady2;
    int i, empty_confirmed;
    idcell_node_poll(n, 0); idcell_node_discovery_status(n, &st); first = st.next_delay_ms; delay = first;
    for (i = 0; i < 9; i++) {
        now += delay; idcell_node_poll(n, now); idcell_node_discovery_status(n, &st);
        delay = st.next_delay_ms; if (delay > max_delay) max_delay = delay;
    }
    idcell_did_generate(0xA102, &hello.src);
    memset(&hello, 0, sizeof(hello)); hello.ver = IDCELL_PROTO_VER_BYTE; hello.type = IDCELL_FT_HELLO;
    idcell_did_generate(0xA102, &hello.src); deliver(n, &hello, now);
    idcell_node_discovery_status(n, &st); empty_confirmed = st.confirmed;
    make_valid_hello(&hello, &hello.src, IDCELL_DISCOVER_ANNOUNCE, NULL, 0); deliver(n, &hello, now);
    idcell_node_discovery_status(n, &st);
    now += st.next_delay_ms; idcell_node_poll(n, now); idcell_node_discovery_status(n, &st); steady1 = st.next_delay_ms;
    now += steady1; idcell_node_poll(n, now); idcell_node_discovery_status(n, &st); steady2 = st.next_delay_ms;
    printf("initial=%u retry_max=%u steady1=%u steady2=%u confirmed=%d failures=%u empty_confirmed=%d\n",
           first, max_delay, steady1, steady2, st.confirmed, st.failures, empty_confirmed);
    idcell_node_free(n); return 1;
}

static int vector_discovery(void)
{
    capture_t c;
    idcell_node_t *n = make_node(0xB101, 1, &c);
    idcell_did_t origin, relay;
    idcell_frame_t f;
    idcell_discovery_status_t st;
    int scope, duplicate, dual_fetch, hop0_forward, hop1_forward;
    idcell_did_generate(0xB110, &origin); idcell_did_generate(0xB111, &relay);
    make_probe(&f, &origin, &origin, 1, "other", 2, ""); deliver(n, &f, 0);
    idcell_node_discovery_status(n, &st); scope = st.last_probe_err;
    make_probe(&f, &origin, &origin, 1, "default", 2, ""); deliver(n, &f, 1);
    make_probe(&f, &relay, &origin, 1, "default", 1, ""); deliver(n, &f, 2);
    idcell_node_discovery_status(n, &st); duplicate = st.last_probe_err; dual_fetch = (int)st.descriptor_fetches;
    hop1_forward = capture_count_type(&c, IDCELL_FT_DISCOVER);
    make_probe(&f, &origin, &origin, 2, "default", 0, ""); deliver(n, &f, 3);
    idcell_node_discovery_status(n, &st);
    hop0_forward = capture_count_type(&c, IDCELL_FT_DISCOVER) - hop1_forward;
    printf("scope=%d duplicate=%d dual_fetches=%d hop0_forward=%d hop1_forward=%d cache_size=%u\n",
           scope, duplicate, dual_fetch, hop0_forward, hop1_forward, st.cache_size);
    idcell_node_free(n);
    n = make_node(0xB103, 0, &c);
    make_probe(&f, &origin, &origin, 9, "default", 0, ""); deliver(n, &f, 0);
    idcell_node_discovery_status(n, &st); printf("unavailable=%d unavailable_cache=%u ", st.last_probe_err, st.cache_size);
    { idcell_capability_t cap; fill_cap(&cap); idcell_node_register_capability(n, &cap); }
    deliver(n, &f, 1); idcell_node_discovery_status(n, &st);
    printf("recovered=%d recovered_fetches=%u\n", st.last_probe_err, st.descriptor_fetches);
    idcell_node_free(n); return 1;
}

static int vector_presence(void)
{
    capture_t c;
    idcell_node_t *n = make_node(0xC101, 0, &c);
    idcell_did_t peer; idcell_frame_t f;
    int ordinary_before, ordinary_offline, scheduled_asleep, scheduled_offline, recovered;
    int explicit_offline, ordinary_after_offline, empty_after_offline, checkin_after_offline;
    idcell_did_generate(0xC102, &peer);
    make_checkin(&f, &peer, IDCELL_WAKE_ALWAYS_ON, 0, 0, 0); deliver(n, &f, 0);
    ordinary_before = idcell_node_peer_presence(n, &peer, 14);
    ordinary_offline = idcell_node_peer_presence(n, &peer, 15);
    make_checkin(&f, &peer, IDCELL_WAKE_SCHEDULED, 20, 30, 1); deliver(n, &f, 20);
    scheduled_asleep = idcell_node_peer_presence(n, &peer, 49);
    scheduled_offline = idcell_node_peer_presence(n, &peer, 50);
    make_checkin(&f, &peer, IDCELL_WAKE_SCHEDULED, 20, 30, 0); deliver(n, &f, 51);
    recovered = idcell_node_peer_presence(n, &peer, 51);
    memset(&f, 0, sizeof(f)); f.ver = IDCELL_PROTO_VER_BYTE; f.type = IDCELL_FT_OFFLINE; f.src = peer;
    deliver(n, &f, 52); explicit_offline = idcell_node_peer_presence(n, &peer, 52);
    f.type = IDCELL_FT_DISCOVER; deliver(n, &f, 53);
    ordinary_after_offline = idcell_node_peer_presence(n, &peer, 53);
    f.type = IDCELL_FT_HELLO; deliver(n, &f, 54);
    empty_after_offline = idcell_node_peer_presence(n, &peer, 54);
    make_checkin(&f, &peer, IDCELL_WAKE_ALWAYS_ON, 0, 0, 0); deliver(n, &f, 55);
    checkin_after_offline = idcell_node_peer_presence(n, &peer, 55);
    printf("ordinary_before=%d ordinary_offline=%d scheduled_asleep=%d scheduled_offline=%d recovered=%d explicit_offline=%d ordinary_after_offline=%d empty_after_offline=%d checkin_after_offline=%d\n",
           ordinary_before, ordinary_offline, scheduled_asleep, scheduled_offline, recovered,
           explicit_offline, ordinary_after_offline, empty_after_offline, checkin_after_offline);
    idcell_node_free(n); return 1;
}

static int vector_relay(void)
{
    capture_t c;
    idcell_node_t *n = make_node(0xB300, 0, &c);
    idcell_did_t origin, target;
    idcell_frame_t f, out;
    idcell_discovery_status_t st;
    int relay_src, relay_dst, relay_hop, send_fault, fault_cache, target_fetch, query_fetch;
    int origin_low, target_low;
    idcell_did_generate(0xB301, &origin); idcell_did_generate(0xB302, &target);
    make_probe_ex(&f, &origin, &origin, 30, "default", 2, "temperature", &target);
    f.dst = target; deliver(n, &f, 1); capture_type(&c, IDCELL_FT_DISCOVER, 0, &out);
    relay_src = (int)idcell_get_u32(out.src.b + 4); relay_dst = (int)idcell_get_u32(out.dst.b + 4);
    origin_low = (int)idcell_get_u32(origin.b + 4); target_low = (int)idcell_get_u32(target.b + 4);
    { const idcell_tlv_t *t = find_tlv(&out, IDCELL_TLV_HOP_LIMIT); relay_hop = t ? t->val[0] : -1; }
    make_probe(&f, &origin, &origin, 31, "default", 1, ""); c.fail_send = 1; deliver(n, &f, 2);
    idcell_node_discovery_status(n, &st); send_fault = st.last_probe_err;
    fault_cache = cache_has(n, &origin, 31);
    idcell_node_free(n);
    n = make_node(0xB303, 1, &c);
    make_probe_ex(&f, &origin, &origin, 32, "default", 1, "temperature", &target); deliver(n, &f, 0);
    idcell_node_discovery_status(n, &st); target_fetch = (int)st.descriptor_fetches;
    make_probe(&f, &origin, &origin, 33, "default", 0, "nonexistent"); deliver(n, &f, 1);
    idcell_node_discovery_status(n, &st); query_fetch = (int)st.descriptor_fetches;
    printf("relay_src=%d relay_dst=%d origin_low=%d target_low=%d relay_hop=%d send_fault=%d fault_cache=%d target_fetch=%d query_fetch=%d\n",
           relay_src, relay_dst, origin_low, target_low, relay_hop, send_fault, fault_cache, target_fetch, query_fetch);
    idcell_node_free(n); return 1;
}

static int vector_mailbox(void)
{
    scene_t s;
    idcell_frame_t w, x;
    idcell_contract_t old;
    int valid, duplicate, expired, old_session, old_epoch, queued;
    int suspended, recovery, reactivated, wake_executed, old_after, nan;
    scene_init(&s); if (!scene_bind(&s)) return 0;
    idcell_node_get_contract(s.dev, &s.host_did, &old);
    prepare_sleep(&s); make_write(&s, &w, 24, 1, 500);
    node_test_receive_frame(s.dev, &w); queued = idcell_node_mailbox_count(s.dev);
    suspended = s.dev->peers[0].suspended;
    idcell_node_wake(s.dev, IDCELL_WAKE_EVENT_PROXY, s.now + 1); s.now++;
    recovery = s.dev->peers[0].recovery;
    idcell_node_poll(s.dev, s.now); wake_executed = s.state.set_calls;
    reactivated = scene_reactivate(&s, old.session_id);
    old_after = deliver_write_result(&s, &w, 24, 1);
    make_write(&s, &w, 24, 2, 500); valid = deliver_write_result(&s, &w, 24, 2);
    duplicate = deliver_write_result(&s, &w, 24, 2);
    make_write(&s, &w, 24, 3, 0); expired = deliver_write_result(&s, &w, 24, 3);
    make_write(&s, &w, 24, 4, 500); x = w; patch_field(&x, IDCELL_TLV_SESSION_ID, 0xFFFF);
    old_session = deliver_write_result(&s, &x, 24, 4);
    x = w; patch_field(&x, IDCELL_TLV_GRANT_EPOCH, 0);
    old_epoch = deliver_write_result(&s, &x, 24, 4);
    make_write(&s, &w, NAN, 5, 500); nan = deliver_write_result(&s, &w, NAN, 5);
    printf("queued=%d suspended=%d recovery=%d reactivated=%d wake_executed=%d old_after=%d valid=%d duplicate=%d expired=%d old_session=%d old_epoch=%d nan=%d executed=%d\n",
           queued, suspended, recovery, reactivated, wake_executed, old_after, valid, duplicate,
           expired, old_session, old_epoch, nan, s.state.set_calls);
    scene_free(&s); return 1;
}

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "--vector") == 0) {
        int ok = 0;
        if (strcmp(argv[2], "announce") == 0) ok = vector_announce();
        else if (strcmp(argv[2], "discovery") == 0) ok = vector_discovery();
        else if (strcmp(argv[2], "presence") == 0) ok = vector_presence();
        else if (strcmp(argv[2], "relay") == 0) ok = vector_relay();
        else if (strcmp(argv[2], "mailbox") == 0) ok = vector_mailbox();
        return ok ? 0 : 2;
    }
    run_tests();
    return d_fail ? 1 : 0;
}
