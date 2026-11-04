/*
 * ID-CELL · 传输适配器
 *
 * 协议本体不含任何传输层代码（L0 可插拔）。绑定层只依赖三个东西：
 *   send(ctx, buf, len)               发送一段字节流
 *   recv(ctx, buf, cap, timeout_ms)   读取一段字节流
 *   profile                           MUST 非空的链路画像（SEC-063）
 *
 * 本文件提供两个现成适配器：
 *   1. 内存回环（loopback）——单进程内把两个节点接在一起，供示例与自测使用
 *   2. 串口适配（serial）——Windows COMx / POSIX ttyUSB·ttyACM
 */
#include "idcell_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#  include <termios.h>
#  include <sys/select.h>
#  include <errno.h>
#endif

/* ---------------------------------------------------------------- 内存回环 */

#define IDCELL_LB_CAP 32768

typedef struct {
    uint8_t data[IDCELL_LB_CAP];
    size_t  rd;
    size_t  wr;
} idcell_lb_ring_t;

struct idcell_loopback {
    idcell_lb_ring_t ring[2];
    idcell_transport_t ep[2];
};

/* 回环的链路画像：介质 = loopback，点对点，无 MTU 概念 */
static const idcell_link_profile_t idcell_lb_profile = {
    IDCELL_MEDIA_LOOPBACK, IDCELL_TOPO_P2P, 0, 0, 0
};

static int lb_write(idcell_lb_ring_t *r, const uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        size_t next = r->wr + 1;
        if (next >= IDCELL_LB_CAP) next = 0;
        if (next == r->rd) return -1;              /* 缓冲区满 */
        r->data[r->wr] = buf[i];
        r->wr = next;
    }
    return 0;
}

static int lb_read(idcell_lb_ring_t *r, uint8_t *buf, size_t cap, uint32_t timeout_ms)
{
    size_t n = 0;
    (void)timeout_ms;   /* 回环是同步内存，不阻塞 */
    while (n < cap && r->rd != r->wr) {
        buf[n++] = r->data[r->rd];
        r->rd = (r->rd + 1 >= IDCELL_LB_CAP) ? 0 : r->rd + 1;
    }
    return (int)n;
}

/* 端点 0：发往端点 1，从自己的环读取 */
static int lb_send_a(void *ctx, const uint8_t *buf, size_t len)
{
    struct idcell_loopback *lb = (struct idcell_loopback *)ctx;
    return lb_write(&lb->ring[1], buf, len);
}

static int lb_recv_a(void *ctx, uint8_t *buf, size_t cap, uint32_t timeout_ms)
{
    struct idcell_loopback *lb = (struct idcell_loopback *)ctx;
    return lb_read(&lb->ring[0], buf, cap, timeout_ms);
}

static int lb_send_b(void *ctx, const uint8_t *buf, size_t len)
{
    struct idcell_loopback *lb = (struct idcell_loopback *)ctx;
    return lb_write(&lb->ring[0], buf, len);
}

static int lb_recv_b(void *ctx, uint8_t *buf, size_t cap, uint32_t timeout_ms)
{
    struct idcell_loopback *lb = (struct idcell_loopback *)ctx;
    return lb_read(&lb->ring[1], buf, cap, timeout_ms);
}

idcell_loopback_t *idcell_loopback_new(void)
{
    struct idcell_loopback *lb = (struct idcell_loopback *)calloc(1, sizeof(*lb));
    if (!lb) return NULL;

    lb->ep[0].send    = lb_send_a;
    lb->ep[0].recv    = lb_recv_a;
    lb->ep[0].profile = &idcell_lb_profile;
    lb->ep[0].ctx     = lb;

    lb->ep[1].send    = lb_send_b;
    lb->ep[1].recv    = lb_recv_b;
    lb->ep[1].profile = &idcell_lb_profile;
    lb->ep[1].ctx     = lb;

    return lb;
}

void idcell_loopback_free(idcell_loopback_t *lb)
{
    free(lb);
}

int idcell_loopback_endpoints(idcell_loopback_t *lb, idcell_transport_t *a, idcell_transport_t *b)
{
    if (!lb || !a || !b) return IDCELL_E_NODEV;
    *a = lb->ep[0];
    *b = lb->ep[1];
    return IDCELL_OK;
}

/* ---------------------------------------------------------------- 串口适配 */

typedef struct {
#ifdef _WIN32
    HANDLE h;
#else
    int fd;
#endif
    idcell_link_profile_t profile;
} idcell_serial_t;

static int serial_send(void *ctx, const uint8_t *buf, size_t len)
{
#ifdef _WIN32
    idcell_serial_t *s = (idcell_serial_t *)ctx;
    DWORD written = 0;
    if (!WriteFile(s->h, buf, (DWORD)len, &written, NULL)) return -1;
    return (written == len) ? 0 : -1;
#else
    idcell_serial_t *s = (idcell_serial_t *)ctx;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(s->fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
#endif
}

static int serial_recv(void *ctx, uint8_t *buf, size_t cap, uint32_t timeout_ms)
{
#ifdef _WIN32
    idcell_serial_t *s = (idcell_serial_t *)ctx;
    DWORD avail = 0, got = 0;
    if (!PeekNamedPipe(s->h, NULL, 0, NULL, &avail, NULL)) return -1;
    if (avail == 0) {
        if (timeout_ms == 0) return 0;
        if (WaitForSingleObject(s->h, timeout_ms) != WAIT_OBJECT_0) return 0;
        if (!PeekNamedPipe(s->h, NULL, 0, NULL, &avail, NULL)) return -1;
        if (avail == 0) return 0;
    }
    if (avail > cap) avail = (DWORD)cap;
    if (!ReadFile(s->h, buf, avail, &got, NULL)) return -1;
    return (int)got;
#else
    idcell_serial_t *s = (idcell_serial_t *)ctx;
    fd_set rf;
    struct timeval tv;
    int rc;
    ssize_t got;

    FD_ZERO(&rf);
    FD_SET(s->fd, &rf);
    tv.tv_sec  = (long)(timeout_ms / 1000);
    tv.tv_usec = (long)((timeout_ms % 1000) * 1000);

    rc = select(s->fd + 1, &rf, NULL, NULL, timeout_ms ? &tv : NULL);
    if (rc <= 0) return 0;

    got = read(s->fd, buf, cap);
    if (got < 0) return (errno == EINTR) ? 0 : -1;
    return (int)got;
#endif
}

/*
 * 打开串口并返回传输适配器。
 * port  ："COM3" / "\\\\.\\COM3" / "/dev/ttyUSB0"
 * baud  ：9600 / 115200 / 921600 等
 * 链路画像固定为 UART · 点对点；t_link_min_ms 由上层按实测填写。
 */
int idcell_serial_open(const char *port, uint32_t baud, idcell_transport_t *out, void **handle)
{
    idcell_serial_t *s;

    if (!port || !out) return IDCELL_E_NODEV;

    s = (idcell_serial_t *)calloc(1, sizeof(*s));
    if (!s) return IDCELL_E_RANGE;

    s->profile.media       = IDCELL_MEDIA_UART;
    s->profile.topology    = IDCELL_TOPO_P2P;
    s->profile.t_link_min_ms = 0;   /* 上层按实测覆盖 */
    s->profile.mtu         = 0;
    s->profile.host_proxy  = 0;

#ifdef _WIN32
    {
        char path[64];
        wchar_t wpath[64];
        DCB dcb;
        COMMTIMEOUTS to;

        if (port[0] == '\\' || (port[0] == '/' && port[1] == '\\'))
            snprintf(path, sizeof(path), "%s", port);
        else
            snprintf(path, sizeof(path), "\\\\.\\%s", port);
        if (MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 64) == 0) {
            free(s);
            return IDCELL_E_UNSAFE;
        }

        s->h = CreateFileW(wpath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
        if (s->h == INVALID_HANDLE_VALUE) {
            free(s);
            return IDCELL_E_UNSAFE;
        }

        ZeroMemory(&dcb, sizeof(dcb));
        dcb.DCBlength = sizeof(dcb);
        if (!GetCommState(s->h, &dcb)) { CloseHandle(s->h); free(s); return IDCELL_E_UNSAFE; }
        dcb.BaudRate = (DWORD)baud;
        dcb.ByteSize = 8;
        dcb.Parity   = NOPARITY;
        dcb.StopBits = ONESTOPBIT;
        if (!SetCommState(s->h, &dcb)) { CloseHandle(s->h); free(s); return IDCELL_E_UNSAFE; }

        ZeroMemory(&to, sizeof(to));
        to.ReadIntervalTimeout      = MAXDWORD;
        to.ReadTotalTimeoutConstant = 0;
        to.WriteTotalTimeoutConstant = 1000;
        SetCommTimeouts(s->h, &to);
    }
#else
    {
        struct termios tio;
        speed_t sp;

        switch (baud) {
        case 9600:   sp = B9600;   break;
        case 19200:  sp = B19200;  break;
        case 38400:  sp = B38400;  break;
        case 57600:  sp = B57600;  break;
        case 115200: sp = B115200; break;
        case 230400: sp = B230400; break;
        case 921600: sp = B921600; break;
        default:     sp = B115200; break;
        }

        s->fd = open(port, O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (s->fd < 0) { free(s); return IDCELL_E_UNSAFE; }

        if (tcgetattr(s->fd, &tio) != 0) { close(s->fd); free(s); return IDCELL_E_UNSAFE; }
        cfmakeraw(&tio);
        tio.c_cflag |= CLOCAL | CREAD;
        cfsetispeed(&tio, sp);
        cfsetospeed(&tio, sp);
        tio.c_cc[VMIN]  = 0;
        tio.c_cc[VTIME] = 0;
        if (tcsetattr(s->fd, TCSANOW, &tio) != 0) { close(s->fd); free(s); return IDCELL_E_UNSAFE; }
    }
#endif

    out->send    = serial_send;
    out->recv    = serial_recv;
    out->profile = &s->profile;
    out->ctx     = s;
    if (handle) *handle = s;
    return IDCELL_OK;
}

void idcell_serial_close(idcell_transport_t *t)
{
    idcell_serial_t *s;
    if (!t || !t->ctx) return;
    s = (idcell_serial_t *)t->ctx;
#ifdef _WIN32
    if (s->h != INVALID_HANDLE_VALUE) CloseHandle(s->h);
#else
    if (s->fd >= 0) close(s->fd);
#endif
    free(s);
    t->ctx = NULL;
}
