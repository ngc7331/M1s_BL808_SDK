#include "m1s_c906_xram_wifi.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/****************************************************************************
 *                                Send Handle
 ****************************************************************************/
static int m1s_xram_wifi_operation(m1s_xram_wifi_t *obj, enum wifi_operation operation)
{
    struct xram_hdr tx_hdr;
    uint32_t bytes;
    int ret = -1;

    assert(obj != NULL);

    if (m1s_c906_xram_mutex_lock()) {
        return -1;
    }

    tx_hdr.type = M1S_XRAM_TYPE_WIFI;
    tx_hdr.err = WIFI_OP_OK;
    tx_hdr.len = sizeof(m1s_xram_wifi_t);
    obj->op = operation;

    bytes = XRAMRingWrite(XRAM_OP_QUEUE, &tx_hdr, sizeof(struct xram_hdr));
    bytes += XRAMRingWrite(XRAM_OP_QUEUE, obj, sizeof(m1s_xram_wifi_t));
    if (bytes != sizeof(struct xram_hdr) + sizeof(m1s_xram_wifi_t)) {
        printf("xram write operate err.\r\n");
    } else {
        struct xram_hdr *hdr = m1s_c906_xram_plunder_rx_hdr();
        if (hdr && hdr->type == M1S_XRAM_TYPE_WIFI && hdr->err == WIFI_OP_OK && hdr->len == 0) {
            ret = 0;
        } else {
            printf("xram plunder rx hdr err.\r\n");
        }
    }

    m1s_c906_xram_mutex_unlock();
    return ret;
}

int m1s_xram_wifi_init(void)
{
    m1s_xram_wifi_t op = {0};
    return m1s_xram_wifi_operation(&op, XRAM_WIFI_INIT);
}

int m1s_xram_wifi_deinit(void)
{
    m1s_xram_wifi_t op = {0};
    return m1s_xram_wifi_operation(&op, XRAM_WIFI_DEINIT);
}

int m1s_xram_wifi_connect(char *ssid, char *passwd)
{
    m1s_xram_wifi_t op = {0};
    strncpy(op.connect.ssid, ssid, sizeof(op.connect.ssid));
    strncpy(op.connect.passwd, passwd, sizeof(op.connect.passwd));
    return m1s_xram_wifi_operation(&op, XRAM_WIFI_CONNECT);
}

int m1s_xram_wifi_disconnect(void)
{
    m1s_xram_wifi_t op = {0};
    return m1s_xram_wifi_operation(&op, XRAM_WIFI_DISCONNECT);
}

int m1s_xram_wifi_upload_stream(char *ip, uint32_t port)
{
    m1s_xram_wifi_t op = {0};
    strncpy(op.upload_stream.ip, ip, sizeof(op.upload_stream.ip));
    op.upload_stream.port = port;
    return m1s_xram_wifi_operation(&op, XRAM_WIFI_UPLOAD_STREAM);
}

typedef enum {
    FSM_STATE_IDLE,
    FSM_STATE_SENT,
    FSM_STATE_HOLD,
    FSM_STATE_ERROR
} fsm_state_t;

static fsm_state_t http_request_status = FSM_STATE_IDLE;
static char *http_response_buf = NULL;
static int http_response_len = 0;
static int http_response_code = 0;

int m1s_xram_wifi_http_request(const char *host, uint16_t port, const char *uri) {
    if (http_request_status != FSM_STATE_IDLE) return -1;
    http_request_status = FSM_STATE_SENT;
    m1s_xram_wifi_t op = {0};
    strncpy(op.http_request.host, host, sizeof(op.http_request.host));
    op.http_request.port = port;
    strncpy(op.http_request.uri, uri, sizeof(op.http_request.uri));
    return m1s_xram_wifi_operation(&op, XRAM_WIFI_HTTP_REQUEST);
}

int m1s_xram_wifi_http_response(char *buf, int *len) {
    if (http_request_status == FSM_STATE_IDLE) {
        printf("m1s_xram_wifi_http_response: still IDLE, do not call this before m1s_xram_wifi_http_request()\r\n");
        return -1;
    } else if (http_request_status == FSM_STATE_SENT) {
        // printf("m1s_xram_wifi_http_response: waiting for response\r\n");
        return 0;
    } else if (http_request_status == FSM_STATE_ERROR) {
        printf("m1s_xram_wifi_http_response: ERROR acknowledged\r\n");
        http_request_status = FSM_STATE_IDLE;
        return -1;
    }

    if (*len <= http_response_len) {
        printf("m1s_xram_wifi_http_response: buffer too small, %d/%d bytes copied\r\n", *len-1, http_response_len);
        strncpy(buf, http_response_buf, *len - 1);
        buf[*len - 1] = '\0';
    } else { // *len >= http_response_len + 1 (NULL terminated)
        printf("m1s_xram_wifi_http_response: %d bytes copied\r\n", *len);
        strncpy(buf, http_response_buf, (*len = http_response_len));
        buf[http_response_len] = '\0';
    }

    http_response_len = 0;
    vPortFree(http_response_buf);
    http_request_status = FSM_STATE_IDLE;
    return http_response_code;
}

static fsm_state_t get_ip_status = FSM_STATE_IDLE;
static uint32_t get_ip_ip = 0;
static uint32_t get_ip_mask = 0;
static uint32_t get_ip_gw = 0;

int m1s_xram_wifi_get_ip_request(void) {
    m1s_xram_wifi_t op = {0};
    get_ip_status = FSM_STATE_SENT;
    return m1s_xram_wifi_operation(&op, XRAM_WIFI_GET_IP_REQUEST);
}

int m1s_xram_wifi_get_ip_response(uint32_t *ip, uint32_t *mask, uint32_t *gw) {
    if (get_ip_status == FSM_STATE_IDLE) {
        printf("m1s_xram_wifi_get_ip_response: still IDLE, do not call this before m1s_xram_wifi_get_ip_request()\r\n");
        return -1;
    } else if (get_ip_status == FSM_STATE_SENT) {
        // printf("m1s_xram_wifi_get_ip_response: waiting for response\r\n");
        return 0;
    } else if (get_ip_status == FSM_STATE_ERROR) {
        printf("m1s_xram_wifi_get_ip_response: ERROR acknowledged\r\n");
        get_ip_status = FSM_STATE_IDLE;
        return -1;
    }

    if (ip) *ip = get_ip_ip;
    if (mask) *mask = get_ip_mask;
    if (gw) *gw = get_ip_gw;

    get_ip_status = FSM_STATE_IDLE;
    return 1;
}


/****************************************************************************
 *                               Recv Handle
 ****************************************************************************/
static int xram_wifi_http_response(m1s_xram_wifi_t *op) {
    struct xram_hdr hdr = {
        .type = M1S_XRAM_TYPE_WIFI,
        .err  = WIFI_OP_ERR,
        .len  = 0,
    };

    if (http_request_status != FSM_STATE_SENT) {
        printf("xram_wifi_http_response: http_request_status != SENT\r\n");
        goto fail;
    }

    /* respond */
    if (op->http_response.code == 0) {
        http_request_status = FSM_STATE_ERROR;
        printf("xram_wifi_http_response: error occured\r\n");
        goto ok;
    }

    http_response_len = op->http_response.len;
    http_response_code = op->http_response.code;
    printf("xram_wifi_http_response: received %d bytes\r\n", http_response_len);
    http_response_buf = pvPortMalloc(http_response_len);
    if (http_response_buf == NULL) {
        printf("xram_wifi_http_response: alloc buffer error\r\n");
        goto fail;
    }
    XRAMRingRead(XRAM_OP_QUEUE, http_response_buf, http_response_len);
    http_request_status = FSM_STATE_HOLD;

    /* respond */
ok:
    hdr.err = WIFI_OP_OK;

fail:
    if (XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr)) != sizeof(struct xram_hdr)) {
        printf("xram ring write err.\r\n");
        return WIFI_OP_ERR;
    }
    return WIFI_OP_OK;
}

static int xram_wifi_get_ip_response(m1s_xram_wifi_t *op) {
    struct xram_hdr hdr = {
        .type = M1S_XRAM_TYPE_WIFI,
        .err  = WIFI_OP_ERR,
        .len  = 0,
    };

    if (get_ip_status != FSM_STATE_SENT) {
        printf("xram_wifi_get_ip_response: get_ip_status != SENT\r\n");
        goto fail;
    }

    /* respond */
    get_ip_ip = op->ip.ip;
    get_ip_mask = op->ip.mask;
    get_ip_gw = op->ip.gw;
    printf("xram_wifi_get_ip_response: received ip=%08x mask=%08x gw=%08x\r\n", get_ip_ip, get_ip_mask, get_ip_gw);
    get_ip_status = FSM_STATE_HOLD;

    /* respond */
    hdr.err = WIFI_OP_OK;

fail:
    if (XRAMRingWrite(XRAM_OP_QUEUE, &hdr, sizeof(struct xram_hdr)) != sizeof(struct xram_hdr)) {
        printf("xram ring write err.\r\n");
        return WIFI_OP_ERR;
    }
    return WIFI_OP_OK;
}

void m1s_c906_xram_wifi_operation_handle(uint32_t len)
{
    m1s_xram_wifi_t obj_op;
    uint32_t bytes;

    bytes = XRAMRingRead(XRAM_OP_QUEUE, &obj_op, len);
    if (bytes == sizeof(m1s_xram_wifi_t)) {
        switch (obj_op.op) {
            case XRAM_WIFI_HTTP_RESPONSE:
                xram_wifi_http_response(&obj_op);
                break;
            case XRAM_WIFI_GET_IP_RESPONSE:
                xram_wifi_get_ip_response(&obj_op);
                break;
            default: {
                printf("xram wifi operate type err.\r\n");
                break;
            }
        }
    }
}