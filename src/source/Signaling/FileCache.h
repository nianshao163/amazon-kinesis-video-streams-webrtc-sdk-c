/*******************************************
Signaling internal include file
*******************************************/
#ifndef __KINESIS_VIDEO_WEBRTC_FILE_CACHE__
#define __KINESIS_VIDEO_WEBRTC_FILE_CACHE__

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "kvs/config.h"
#include "kvs/error.h"
#include "kvs/common_defs.h"
#include "kvs/webrtc_client.h"
/* If SignalingFileCacheEntry layout is changed, change the version in cache file name so we wont read from older
 * cache file. */
#define MAX_SIGNALING_CACHE_ENTRY_TIMESTAMP_STR_LEN 10
/* Max length for a serialized signaling cache entry. 8 accounts for 6 commas and 1 newline
 * char and null terminator */
#define MAX_SERIALIZED_SIGNALING_CACHE_ENTRY_LEN                                                                                                     \
    MAX_CHANNEL_NAME_LEN + MAX_ARN_LEN + MAX_REGION_NAME_LEN + MAX_SIGNALING_ENDPOINT_URI_LEN * 2 + MAX_SIGNALING_CACHE_ENTRY_TIMESTAMP_STR_LEN + 8
#define MAX_SIGNALING_CACHE_ENTRY_COUNT           32
#define SIGNALING_FILE_CACHE_ROLE_TYPE_MASTER_STR "Master"
#define SIGNALING_FILE_CACHE_ROLE_TYPE_VIEWER_STR "Viewer"

typedef struct {
    SIGNALING_CHANNEL_ROLE_TYPE role;
    UINT64 creationTsEpochSeconds;
    CHAR channelName[MAX_CHANNEL_NAME_LEN + 1];
    CHAR channelArn[MAX_ARN_LEN + 1];
    CHAR region[MAX_REGION_NAME_LEN + 1];
    CHAR httpsEndpoint[MAX_SIGNALING_ENDPOINT_URI_LEN + 1];
    CHAR wssEndpoint[MAX_SIGNALING_ENDPOINT_URI_LEN + 1];
} SignalingFileCacheEntry, *PSignalingFileCacheEntry;

STATUS signalingCacheLoadFromFile(PCHAR, PCHAR, SIGNALING_CHANNEL_ROLE_TYPE, PSignalingFileCacheEntry, PBOOL);
STATUS signalingCacheSaveToFile(PSignalingFileCacheEntry);

#ifdef __cplusplus
}
#endif
#endif /* __KINESIS_VIDEO_WEBRTC_FILE_CACHE__ */
