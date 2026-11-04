/*
 * ID-CELL 参考实现 · 传输适配器（公开接口）
 *
 * 协议本体不含传输层代码（L0 可插拔）。绑定层只需要三样东西：
 *   1) send  —— 发一段字节流
 *   2) recv  —— 读一段字节流
 *   3) profile —— 链路画像，MUST 非空（SEC-063：声明物理拓扑与主机代发范围）
 *
 * 自带两个现成适配器：
 *   idcell_loopback_*  内存回环，供单进程内把两个节点接起来（示例与自测）
 *   idcell_serial_*    串口（Windows COMx / POSIX ttyUSB·ttyACM）
 */
#ifndef IDCELL_TRANSPORT_H
#define IDCELL_TRANSPORT_H

#include "idcell.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------- 内存回环 */

typedef struct idcell_loopback idcell_loopback_t;

/* 创建一条回环链路 */
idcell_loopback_t *idcell_loopback_new(void);
void idcell_loopback_free(idcell_loopback_t *lb);

/* 取两端适配器：A 端与 B 端互为对端 */
int idcell_loopback_endpoints(idcell_loopback_t *lb,
                              idcell_transport_t *a, idcell_transport_t *b);

/* ---------------------------------------------------------------- 串口 */

/*
 * 打开串口。port 形如 "COM3" / "\\\\.\\COM3" / "/dev/ttyUSB0"；
 * baud 形如 9600 / 115200 / 921600。
 * 返回 IDCELL_OK 时 out->send / out->recv / out->profile 均已填好。
 */
int idcell_serial_open(const char *port, uint32_t baud,
                        idcell_transport_t *out, void **handle);

/* 关闭串口并释放句柄（同时把 out 清空） */
void idcell_serial_close(idcell_transport_t *t);

#ifdef __cplusplus
}
#endif
#endif /* IDCELL_TRANSPORT_H */
