#ifndef __M1S_COMMON_XRAM_WIFI_H
#define __M1S_COMMON_XRAM_WIFI_H

#include <stdint.h>

typedef enum wifi_op_err {
    WIFI_OP_OK,
    WIFI_OP_ERR,
} WIFI_OP_ERR_TYPE;

enum wifi_operation {
    XRAM_WIFI_INIT,
    XRAM_WIFI_DEINIT,
    XRAM_WIFI_CONNECT,
    XRAM_WIFI_DISCONNECT,
    XRAM_WIFI_UPLOAD_STREAM,
    XRAM_WIFI_HTTP_REQUEST,
    XRAM_WIFI_HTTP_RESPONSE,
    XRAM_WIFI_GET_IP_REQUEST,
    XRAM_WIFI_GET_IP_RESPONSE,
};

struct m1s_xram_wifi {
    uint32_t op;
    union {
        struct {
            char ssid[32];
            char passwd[63];
        } __attribute__((packed)) connect;

        struct {
            uint32_t port;
            char ip[16];
        } __attribute__((packed)) upload_stream;

        struct {
            char host[32];
            uint16_t port;
            char uri[80];
        } __attribute__((packed)) http_request;

        struct {
            struct {
                short major;
                short minor;
            } __attribute__((packed)) version;
            int code;     // http status code
            char type[32]; // content-type
            int len;       // content-length
            // content will be sent after this struct
        } __attribute__((packed)) http_response;

        struct {
            uint32_t ip;
            uint32_t mask;
            uint32_t gw;
        } __attribute__((packed)) ip;
    };
} __attribute__((packed));
typedef struct m1s_xram_wifi m1s_xram_wifi_t;

#endif
