/*******************************************
Main internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_CLIENT_INCLUDE_I__
#define __KINESIS_VIDEO_WEBRTC_CLIENT_INCLUDE_I__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#endif

////////////////////////////////////////////////////
// Project include files
////////////////////////////////////////////////////
#include <kvs/webrtc_client.h>

#ifdef KVS_USE_OPENSSL
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#elif KVS_USE_MBEDTLS
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/certs.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md5.h>
#endif

#ifdef KVS_PLAT_RTK_FREERTOS
#include <srtp.h>
#else
#include <srtp2/srtp.h>
#endif

// INET/INET6 MUST be defined before usrsctp
// If removed will cause corruption that is hard to determine at runtime
#define INET 1
//#define INET6 1
#include <usrsctp.h>

// Max uFrag and uPwd length as documented in https://tools.ietf.org/html/rfc5245#section-15.4
#define ICE_MAX_UFRAG_LEN 256
#define ICE_MAX_UPWD_LEN  256

// Max stun username attribute len: https://tools.ietf.org/html/rfc5389#section-15.3
#define STUN_MAX_USERNAME_LEN (UINT16) 512

// https://tools.ietf.org/html/rfc5389#section-15.7
#define STUN_MAX_REALM_LEN (UINT16) 128

// https://tools.ietf.org/html/rfc5389#section-15.8
#define STUN_MAX_NONCE_LEN (UINT16) 128

// https://tools.ietf.org/html/rfc5389#section-15.6
#define STUN_MAX_ERROR_PHRASE_LEN (UINT16) 128

// Byte sizes of the IP addresses
#define IPV6_ADDRESS_LENGTH (UINT16) 16
#define IPV4_ADDRESS_LENGTH (UINT16) 4

#define CERTIFICATE_FINGERPRINT_LENGTH 160

#define MAX_UDP_PACKET_SIZE 65507

#define IS_IPV4_ADDR(pAddress) ((pAddress)->family == KVS_IP_FAMILY_TYPE_IPV4)

// Used for ensuring alignment
#define ALIGN_UP_TO_MACHINE_WORD(x) ROUND_UP((x), SIZEOF(SIZE_T))

////////////////////////////////////////////////////
// Project forward declarations
////////////////////////////////////////////////////
struct __TurnConnection;
struct __SocketConnection;
STATUS generateJSONSafeString(PCHAR, UINT32);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_CLIENT_INCLUDE_I__ */
