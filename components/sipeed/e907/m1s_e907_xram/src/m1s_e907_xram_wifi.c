#include "m1s_e907_xram_wifi.h"

#include <aos/yloop.h>
#include <assert.h>
#include <bl60x_fw_api.h>
#include <bl_phy_api.h>
#include <hal_wifi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <wifi_mgmr_ext.h>
#include <xram.h>
#include "bl_cam.h"
#include <lwip/api.h>
#include <lwip/tcpip.h>
#include <lwip/sockets.h>
#include <lwip/tcp.h>
#include <lwip/err.h>

#include "FreeRTOS.h"
#include "bl808_common.h"
#include "bl808_glb.h"
#include "bl_timer.h"
#include "queue.h"
#include "softcrc.h"

static struct {
    uint16_t port;
    char ip[16];
    TaskHandle_t upload_stream_handle;
    uint8_t *stream_buff;
    uint8_t got_ip;
} private;
/****************************************************************************
 *                               Recv Handle
 ****************************************************************************/
static void wifi_event_cb(input_event_t *event, void *private_data)
{
    switch (event->code) {
        case CODE_WIFI_ON_GOT_IP: {
            printf("[APP] [EVT] GOT IP\r\n");
            private.got_ip = 1;
        } break;
        default: {
            printf("[APP] [EVT] Unknown code %u\r\n", event->code);
        }
    }
}

static int wifi_init()
{
    static uint8_t stack_wifi_init = 0;
    if (1 == stack_wifi_init) {
        puts("Wi-Fi Stack Started already!!!\r\n");
        return 0;
    }

    /* remove this usage when c89 */
    phy_powroffset_set((int8_t[4]){0x0, 0x0, 0x0, 0x0});
    bl_tpc_update_power_rate_11b((int8_t[4]){0x14, 0x14, 0x14, 0x12});
    bl_tpc_update_power_rate_11g((int8_t[8]){0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0xe, 0xe});
    bl_tpc_update_power_rate_11n((int8_t[8]){0x12, 0x12, 0x12, 0x12, 0x12, 0x10, 0xe, 0xe});

    printf("Start Wi-Fi fw @%lums\r\n", bl_timer_now_us() / 1000);
    hal_wifi_start_firmware_task();
    /*Trigger to start Wi-Fi*/
    printf("Start Wi-Fi fw is Done @%lums\r\n", bl_timer_now_us() / 1000);
    vTaskDelay(1000);
    aos_post_event(EV_WIFI, CODE_WIFI_ON_INIT_DONE, 0);
    aos_register_event_filter(EV_WIFI, wifi_event_cb, NULL);
    stack_wifi_init = 1;
    return 0;
}

static int xram_wifi_init(m1s_xram_wifi_t *op)
{
    struct xram_hdr hdr;
    uint32_t bytes;
    enum wifi_op_err err = WIFI_OP_OK;

    /* wifi init */
    if (0 != wifi_init()) {
        err = WIFI_OP_ERR;
    }

    /* xram response */
    hdr.type = M1S_XRAM_TYPE_WIFI;
    hdr.err = err;
    hdr.len = 0;
    bytes = XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr));
    if (bytes == sizeof(struct xram_hdr)) {
        return WIFI_OP_OK;
    } else {
        printf("xram ring write err.\r\n");
        return WIFI_OP_ERR;
    }
}

static void wifi_deinit() {}

static int xram_wifi_deinit(m1s_xram_wifi_t *op)
{
    struct xram_hdr hdr;
    uint32_t bytes;

    /* wifi deinit */
    wifi_deinit();

    /* xram response */
    hdr.type = M1S_XRAM_TYPE_WIFI;
    hdr.err = WIFI_OP_OK;
    hdr.len = 0;
    bytes = XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr));
    if (bytes == sizeof(struct xram_hdr)) {
        return WIFI_OP_OK;
    } else {
        printf("xram ring write err.\r\n");
        return WIFI_OP_ERR;
    }
}

static int wifi_connect(char *ssid, char *passwd)
{
    wifi_interface_t wifi_interface;
    wifi_interface = wifi_mgmr_sta_enable();
    wifi_mgmr_sta_connect_mid(wifi_interface,
                              ssid,    // 网络名称
                              passwd,  // 密码
                              NULL,    // 用于快速漫游，以用于在切换区域时保证网络不中断
                              NULL,    //
                              0, 0, 1, WIFI_CONNECT_STOP_SCAN_CURRENT_CHANNEL_IF_TARGET_AP_FOUND);
    return 0;
}

static int xram_wifi_connect(m1s_xram_wifi_t *op)
{
    struct xram_hdr hdr;
    uint32_t bytes;

    /* wifi deinit */
    wifi_connect(op->connect.ssid, op->connect.passwd);

    /* xram response */
    hdr.type = M1S_XRAM_TYPE_WIFI;
    hdr.err = WIFI_OP_OK;
    hdr.len = 0;
    bytes = XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr));
    if (bytes == sizeof(struct xram_hdr)) {
        return WIFI_OP_OK;
    } else {
        printf("xram ring write err.\r\n");
        return WIFI_OP_ERR;
    }
}

static void wifi_disconnect() {}

static int xram_wifi_disconnect(m1s_xram_wifi_t *op)
{
    struct xram_hdr hdr;
    uint32_t bytes;

    /* wifi deinit */
    wifi_disconnect();

    /* xram response */
    hdr.type = M1S_XRAM_TYPE_WIFI;
    hdr.err = WIFI_OP_OK;
    hdr.len = 0;
    bytes = XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr));
    if (bytes == sizeof(struct xram_hdr)) {
        return WIFI_OP_OK;
    } else {
        printf("xram ring write err.\r\n");
        return WIFI_OP_ERR;
    }
}

static void upload_stream_task(void *param)
{
    while (0 == private.got_ip) {
        vTaskDelay(1);
    }
    int ret = 0;
    uint32_t mjpeg_start_addr, mjpeg_buffer_size;

    uint8_t *pic, *usb_ptr;
    uint32_t len, first_len, second_len;

    int sock = -1;
    struct sockaddr_in client_addr;
_retry:
    ret = bl_cam_mjpeg_buffer_info_get(&mjpeg_start_addr, &mjpeg_buffer_size);
    if (ret != 0) {
        printf("mjpeg not init\r\n");
        vTaskDelay(50);
        goto _retry;
    }
    printf("mjpeg init is ok!\r\n");

    #define PER_FRAME_MJPEG      120*1024
    if (private.stream_buff) {
        vPortFree(private.stream_buff);
        private.stream_buff = NULL;
    }
    private.stream_buff = pvPortMalloc(PER_FRAME_MJPEG);
    if (NULL == private.stream_buff) {
        printf("malloc fail!\r\n");
        goto exit;
    }
    while (1) {
        vTaskDelay(100);
        printf("Socket connect..\r\n");
        if (0 > (sock = socket(AF_INET, SOCK_STREAM, 0))) {
            continue;
        }

        client_addr.sin_family = AF_INET;
        client_addr.sin_port = htons(private.port);
        client_addr.sin_addr.s_addr = inet_addr(private.ip);
        memset(&(client_addr.sin_zero), 0, sizeof(client_addr.sin_zero));
        
        if(-1 == connect(sock,
                        (struct sockaddr *)&client_addr,
                        sizeof(struct sockaddr)))
        {
            closesocket(sock);
            continue;
        }

        while (1) {
            ret = bl_cam_mjpeg_get(&pic, &len);
            csi_dcache_invalid_range((void *)pic, len);
            if (ret == 0) {
                if (((uint32_t)(uintptr_t)pic + len) > (mjpeg_start_addr + mjpeg_buffer_size)) {
                    /* if mjpeg store edge loop to start*/
                    first_len = mjpeg_start_addr + mjpeg_buffer_size - (uint32_t)(uintptr_t)pic;
                    second_len = len - first_len;
                    csi_dcache_invalid_range((void *)pic, first_len);
                    memcpy(private.stream_buff, pic, first_len);
                    csi_dcache_invalid_range((void *)mjpeg_start_addr, second_len);
                    memcpy(private.stream_buff + first_len, (void *)mjpeg_start_addr, second_len);
                    usb_ptr = private.stream_buff;
                } else {
                    /*mjpeg data not cut*/
                    usb_ptr = pic;
                    csi_dcache_invalid_range((void *)usb_ptr, len);
                }

                uint8_t recv;
_retry2:
                printf("send jpg len(%d):%ld\r\n", sizeof(len), len);
                if (write(sock, &len, sizeof(len)) < 0) break;
                if (read(sock, &recv, 1) < 0) {
                    vTaskDelay(50);
                    goto _retry2;
                }

                #define PACK_LEN    (1000)
                int remain_len = len;

                if (write(sock, usb_ptr, remain_len) < 0) break;

                bl_cam_mjpeg_pop();
            }
        }
        closesocket(sock);
    }

exit:
    vTaskDelete(NULL);
}
static void wifi_upload_stream(void)
{
    if (private.upload_stream_handle) {
        vTaskDelete(private.upload_stream_handle);
        private.upload_stream_handle = NULL;
    }

    xTaskCreate(upload_stream_task, (char *)"upload stream", 512, NULL, 15, &private.upload_stream_handle);
}

static int xram_wifi_upload_stream(m1s_xram_wifi_t *op)
{
    struct xram_hdr hdr;
    uint32_t bytes;

    /* wifi upload camera stream */
    private.port = op->upload_stream.port;
    strcpy(private.ip, op->upload_stream.ip);
    wifi_upload_stream();

    /* xram response */
    hdr.type = M1S_XRAM_TYPE_WIFI;
    hdr.err = WIFI_OP_OK;
    hdr.len = 0;
    bytes = XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr));
    if (bytes == sizeof(struct xram_hdr)) {
        return WIFI_OP_OK;
    } else {
        printf("xram ring write err.\r\n");
        return WIFI_OP_ERR;
    }
}

#define HTTP_REQUEST_BUFSIZE 1024
#define HTTP_REQUEST_ENABLE_LOG
static int xram_wifi_http_request(m1s_xram_wifi_t *op)
{
    struct xram_hdr hdr = {
        .type = M1S_XRAM_TYPE_WIFI,
        .err  = WIFI_OP_OK,
        .len  = 0,
    };
    m1s_xram_wifi_t resp = {
        .op = XRAM_WIFI_HTTP_RESPONSE,
        .http_response = {
            .version = {0, 0},
            .code = 0,
            .type = {0},
            .len  = 0,
        }
    };
    uint32_t bytes;

    /* alloc buffer */
    char *buf = pvPortMalloc(HTTP_REQUEST_BUFSIZE);
    if (NULL == buf) {
        printf("xram_wifi_http_request: alloc buffer error\r\n");
        hdr.err = WIFI_OP_ERR;
        if (XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr)) != sizeof(struct xram_hdr)) {
            printf("xram ring write err.\r\n");
            return WIFI_OP_ERR;
        }
        return WIFI_OP_OK;
    }

    /* respond */
    if (XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr)) != sizeof(struct xram_hdr)) {
        printf("xram ring write err.\r\n");
        return WIFI_OP_ERR;
    }

    /* send real http request */
    // resolve host ip
    char *host_ip;
#ifdef LWIP_DNS
    ip4_addr_t dns_result;
    netconn_gethostbyname(op->http_request.host, &dns_result);
    host_ip = ip_ntoa(&dns_result);
#else
    host_ip = op->http_request.host;
#endif

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("xram_wifi_http_request: open socket error\r\n");
        goto fail;
    }

#ifdef HTTP_REQUEST_ENABLE_LOG
    printf("xram_wifi_http_request: connecting to %s:%d\r\n", host_ip, op->http_request.port == 0 ? 80 : op->http_request.port);
#endif

    struct sockaddr_in host_addr;
    host_addr.sin_family = AF_INET;
    host_addr.sin_addr.s_addr = inet_addr(host_ip);
    host_addr.sin_port = htons(op->http_request.port == 0 ? 80 : op->http_request.port);
    memset(&(host_addr.sin_zero), 0, sizeof(host_addr.sin_zero));

    int ret = connect(sock, (struct sockaddr *)&host_addr, sizeof(struct sockaddr));
    if (ret < 0) {
        printf("xram_wifi_http_request: connect failed(%d)\r\n", ret);
        goto fail;
    }

    // construct HTTP packet
    // TODO: support PUT/OPTION/DELETE
    // TODO: headers
    ret = snprintf(buf, HTTP_REQUEST_BUFSIZE,
        "%s %s HTTP/1.1\r\nHOST: %s\r\n\r\n\r\n\r\n",
        "GET",
        op->http_request.uri, op->http_request.host
    );

    // send
    if ((ret = write(sock, buf, ret)) < 0) {
        printf("xram_wifi_http_request: write failed\r\n");
        goto fail;
    }

    // clear buffer
    memset(buf, 0, HTTP_REQUEST_BUFSIZE);

    // recv
    if ((ret = recv(sock, buf, HTTP_REQUEST_BUFSIZE, 0)) < 0) {
        printf("xram_wifi_http_request: recv failed\r\n");
        goto fail;
    }

#ifdef HTTP_REQUEST_ENABLE_LOG
    printf("xram_wifi_http_request: recv %d bytes\r\n", ret);
#endif

    // close socket
    closesocket(sock);

    // destruct HTTP packet
    // TODO: cookies, etc.
    char *pbuf = buf;
    sscanf(buf, "HTTP/%hd.%hd %d", &resp.http_response.version.major, &resp.http_response.version.minor, &resp.http_response.code);
#ifdef HTTP_REQUEST_ENABLE_LOG
    printf("xram_wifi_http_request: found HTTP version %hd.%hd, status %d\r\n", resp.http_response.version.major, resp.http_response.version.minor, resp.http_response.code);
#endif
    do {
        while (*(pbuf++) != '\n') ; // goto next line
        if (sscanf(pbuf, "Content-Type: %s\r\n", resp.http_response.type) == 1) {
#ifdef HTTP_REQUEST_ENABLE_LOG
            printf("xram_wifi_http_request: found Content-Type: %s\r\n", resp.http_response.type);
#endif
        }
        if (sscanf(pbuf, "Content-Length: %d\r\n", &resp.http_response.len) == 1) {
#ifdef HTTP_REQUEST_ENABLE_LOG
            printf("xram_wifi_http_request: found Content-Length: %d\r\n", resp.http_response.len);
#endif
        }
    } while (*pbuf != '\r'); // until empty line
    pbuf += 2; // skip empty line

    // pass response to C906 core through XRAM
    hdr.len = sizeof(m1s_xram_wifi_t);
    bytes  = XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr));
    bytes += XRAMRingWrite(XRAM_OP_QUEUE, &resp, sizeof(m1s_xram_wifi_t));
    bytes += XRAMRingWrite(XRAM_OP_QUEUE, pbuf, resp.http_response.len);

    // free buffer
    vPortFree(buf);
    if (bytes != sizeof(struct xram_hdr) + sizeof(m1s_xram_wifi_t) + resp.http_response.len) {
        printf("xram ring write err.\r\n");
        return WIFI_OP_ERR;
    }
    return WIFI_OP_OK;

    /* failed */
fail:
    // close socket
    closesocket(sock);

    // send response
    hdr.len = sizeof(m1s_xram_wifi_t);
    bytes  = XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr));
    bytes += XRAMRingWrite(XRAM_OP_QUEUE, &resp, sizeof(m1s_xram_wifi_t));

    // free buffer
    vPortFree(buf);
    if (bytes != sizeof(struct xram_hdr) + sizeof(m1s_xram_wifi_t)) {
        printf("xram ring write err.\r\n");
        return WIFI_OP_ERR;
    }
    return WIFI_OP_OK;
}

void m1s_e907_xram_wifi_operation_handle(uint32_t len)
{
    m1s_xram_wifi_t obj_op;
    uint32_t bytes;

    bytes = XRAMRingRead(XRAM_OP_QUEUE, &obj_op, len);
    if (bytes == sizeof(m1s_xram_wifi_t)) {
        switch (obj_op.op) {
            case XRAM_WIFI_INIT: {
                xram_wifi_init(&obj_op);
                break;
            }
            case XRAM_WIFI_DEINIT: {
                xram_wifi_deinit(&obj_op);
                break;
            }
            case XRAM_WIFI_CONNECT: {
                xram_wifi_connect(&obj_op);
                break;
            }
            case XRAM_WIFI_DISCONNECT: {
                xram_wifi_disconnect(&obj_op);
                break;
            }
            case XRAM_WIFI_UPLOAD_STREAM: {
                xram_wifi_upload_stream(&obj_op);
                break;
            }
            case XRAM_WIFI_HTTP_REQUEST: {
                xram_wifi_http_request(&obj_op);
                break;
            }
            default: {
                printf("xram wifi operate type err.\r\n");
                break;
            }
        }
    }
}
