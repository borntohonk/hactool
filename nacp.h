#ifndef HACTOOL_NACP_H
#define HACTOOL_NACP_H

#include "types.h"
#include "settings.h"
#include "cJSON.h"

#define NACP_TOTAL_SIZE 0x4000

/* Single-byte enum types */
typedef enum {
    NACP_STARTUP_USER_ACCOUNT_NONE    = 0,
    NACP_STARTUP_USER_ACCOUNT_REQUIRED = 1,
    NACP_STARTUP_USER_ACCOUNT_REQUIRED_WITH_NETWORK_SERVICE = 2,
} nacp_startup_user_account_t;

typedef enum {
    NACP_USER_ACCOUNT_SWITCH_LOCK_DISABLE = 0,
    NACP_USER_ACCOUNT_SWITCH_LOCK_ENABLE  = 1,
} nacp_user_account_switch_lock_t;

typedef enum {
    NACP_ADD_ON_CONTENT_REGISTRATION_TYPE_ALL_ON_LAUNCH = 0,
    NACP_ADD_ON_CONTENT_REGISTRATION_TYPE_ON_DEMAND     = 1,
} nacp_add_on_content_registration_type_t;

typedef enum {
    NACP_SCREENSHOT_ALLOW = 0,
    NACP_SCREENSHOT_DENY  = 1,
} nacp_screenshot_t;

typedef enum {
    NACP_VIDEO_CAPTURE_DISABLE = 0,
    NACP_VIDEO_CAPTURE_MANUAL  = 1,
    NACP_VIDEO_CAPTURE_ENABLE  = 2,
} nacp_video_capture_t;

typedef enum {
    NACP_DATA_LOSS_CONFIRMATION_NONE     = 0,
    NACP_DATA_LOSS_CONFIRMATION_REQUIRED = 1,
} nacp_data_loss_confirmation_t;

typedef enum {
    NACP_PLAY_LOG_POLICY_OPEN     = 0,
    NACP_PLAY_LOG_POLICY_LOG_ONLY = 1,
    NACP_PLAY_LOG_POLICY_NONE     = 2,
    NACP_PLAY_LOG_POLICY_CLOSED   = 3,
} nacp_play_log_policy_t;

typedef enum {
    NACP_LOGO_TYPE_LICENSED_BY_NINTENDO    = 0,
    NACP_LOGO_TYPE_DISTRIBUTED_BY_NINTENDO = 1,
    NACP_LOGO_TYPE_NINTENDO                = 2,
} nacp_logo_type_t;

typedef enum {
    NACP_LOGO_HANDLING_AUTO   = 0,
    NACP_LOGO_HANDLING_MANUAL = 1,
} nacp_logo_handling_t;

typedef enum {
    NACP_RUNTIME_ADD_ON_CONTENT_INSTALL_DENY                                    = 0,
    NACP_RUNTIME_ADD_ON_CONTENT_INSTALL_ALLOW_APPEND                            = 1,
    NACP_RUNTIME_ADD_ON_CONTENT_INSTALL_ALLOW_APPEND_BUT_DONT_DOWNLOAD_ON_NETWORK = 2,
} nacp_runtime_add_on_content_install_t;

typedef enum {
    NACP_RUNTIME_PARAMETER_DELIVERY_ALWAYS                   = 0,
    NACP_RUNTIME_PARAMETER_DELIVERY_ALWAYS_IF_USER_MATCHED   = 1,
    NACP_RUNTIME_PARAMETER_DELIVERY_ON_RESTART               = 2,
} nacp_runtime_parameter_delivery_t;

typedef enum {
    NACP_APPROPRIATE_AGE_FOR_CHINA_NONE  = 0,
    NACP_APPROPRIATE_AGE_FOR_CHINA_AGE_8  = 1,
    NACP_APPROPRIATE_AGE_FOR_CHINA_AGE_12 = 2,
    NACP_APPROPRIATE_AGE_FOR_CHINA_AGE_16 = 3,
} nacp_appropriate_age_for_china_t;

typedef enum {
    NACP_CRASH_REPORT_DENY  = 0,
    NACP_CRASH_REPORT_ALLOW = 1,
} nacp_crash_report_t;

typedef enum {
    NACP_HDCP_NONE     = 0,
    NACP_HDCP_REQUIRED = 1,
} nacp_hdcp_t;

typedef enum {
    NACP_PLAY_LOG_QUERY_CAPABILITY_NONE       = 0,
    NACP_PLAY_LOG_QUERY_CAPABILITY_WHITE_LIST = 1,
    NACP_PLAY_LOG_QUERY_CAPABILITY_ALL        = 2,
} nacp_play_log_query_capability_t;

typedef enum {
    NACP_TITLES_DATA_FORMAT_FORMAT0 = 0,
    NACP_TITLES_DATA_FORMAT_FORMAT1 = 1,
} nacp_titles_data_format_t;

typedef enum {
    NACP_APPARENT_PLATFORM_NX       = 0,
    NACP_APPARENT_PLATFORM_SWITCH_2 = 1,
} nacp_apparent_platform_t;

/* Rating organization indices */
typedef enum {
    NACP_RATING_ORG_CERO     = 0,
    NACP_RATING_ORG_GRACGCRB = 1,
    NACP_RATING_ORG_CLASSIND = 2,
    NACP_RATING_ORG_USK      = 3,
    NACP_RATING_ORG_ESRB     = 4,
    NACP_RATING_ORG_RLAOA    = 5,
    NACP_RATING_ORG_GENERIC  = 6,
    NACP_RATING_ORG_PEGI     = 7,
    NACP_RATING_ORG_PEGI_PORTUGUESE = 8,
    NACP_RATING_ORG_PIDVD    = 9,
    NACP_RATING_ORG_MOBAGEAGEREATING = 10,
    NACP_RATING_ORG_MTTA     = 11,
    NACP_RATING_ORG_CERO2    = 12,
    NACP_RATING_ORG_COUNT    = 13,
} nacp_rating_org_t;

/* Per-language application title entry (0x300 bytes each) */
#pragma pack(push, 1)
typedef struct {
    char name[0x200];
    char publisher[0x100];
} nacp_application_title_t;

/* Full NACP binary layout — exactly 0x4000 bytes */
typedef struct {
    /* 0x0000: Title section — Format0: 16 × 0x300 ApplicationTitle entries.
     *         Format1: u16 compressed_size followed by raw-deflate stream.
     *         Check titles_data_format (at 0x3215) before interpreting. */
    nacp_application_title_t titles[16];            /* 0x0000, 0x3000 bytes */

    /* Properties section — always at 0x3000 regardless of TitlesDataFormat */
    char   isbn[0x25];                              /* 0x3000 */
    uint8_t startup_user_account;                   /* 0x3025 */
    uint8_t user_account_switch_lock;               /* 0x3026 */
    uint8_t add_on_content_registration_type;       /* 0x3027 */
    uint32_t attribute_flag;                        /* 0x3028 */
    uint32_t supported_language_flag;               /* 0x302C */
    uint32_t parental_control_flag;                 /* 0x3030 */
    uint8_t screenshot;                             /* 0x3034 */
    uint8_t video_capture;                          /* 0x3035 */
    uint8_t data_loss_confirmation;                 /* 0x3036 */
    uint8_t play_log_policy;                        /* 0x3037 */
    uint64_t presence_group_id;                     /* 0x3038 */
    uint8_t rating_age[0x20];                       /* 0x3040, 13 used + padding */
    char   display_version[0x10];                   /* 0x3060 */
    uint64_t add_on_content_base_id;                /* 0x3070 */
    uint64_t save_data_owner_id;                    /* 0x3078 */
    uint64_t user_account_save_data_size;           /* 0x3080 */
    uint64_t user_account_save_data_journal_size;   /* 0x3088 */
    uint64_t device_save_data_size;                 /* 0x3090 */
    uint64_t device_save_data_journal_size;         /* 0x3098 */
    uint64_t bcat_delivery_cache_storage_size;      /* 0x30A0 */
    char   application_error_code_category[0x8];   /* 0x30A8 */
    uint64_t local_communication_id;                /* 0x30B0 */
    uint8_t _0x30B8[0x38];                          /* 0x30B8 reserved */
    uint8_t logo_type;                              /* 0x30F0 */
    uint8_t logo_handling;                          /* 0x30F1 */
    uint8_t runtime_add_on_content_install;         /* 0x30F2 */
    uint8_t runtime_parameter_delivery;             /* 0x30F3 */
    uint8_t appropriate_age_for_china;              /* 0x30F4 */
    uint8_t _0x30F5;                                /* 0x30F5 reserved */
    uint8_t crash_report;                           /* 0x30F6 */
    uint8_t hdcp;                                   /* 0x30F7 */
    uint64_t seed_for_pseudo_device_id;             /* 0x30F8 */
    char   bcat_passphrase[0x41];                   /* 0x3100 */
    uint8_t startup_user_account_option;            /* 0x3141 */
    uint8_t _0x3142[0x6];                           /* 0x3142 reserved */
    uint64_t user_account_save_data_size_max;       /* 0x3148 */
    uint64_t user_account_save_data_journal_size_max; /* 0x3150 */
    uint64_t device_save_data_size_max;             /* 0x3158 */
    uint64_t device_save_data_journal_size_max;     /* 0x3160 */
    uint64_t temporary_storage_size;                /* 0x3168 */
    uint64_t cache_storage_size;                    /* 0x3170 */
    uint64_t cache_storage_journal_size;            /* 0x3178 */
    uint64_t cache_storage_data_and_journal_size_max; /* 0x3180 */
    uint16_t cache_storage_index_max;               /* 0x3188 */
    uint8_t _0x318A;                                /* 0x318A reserved */
    uint8_t runtime_upgrade;                        /* 0x318B */
    uint32_t supporting_limited_application_licenses; /* 0x318C */
    uint64_t play_log_queryable_application_ids[16]; /* 0x3190 */
    uint8_t play_log_query_capability;              /* 0x3210 */
    uint8_t repair_flag;                            /* 0x3211 */
    uint8_t program_index;                          /* 0x3212 */
    uint8_t required_network_service_license_on_launch_flag; /* 0x3213 */
    uint8_t application_error_code_prefix;          /* 0x3214 */
    uint8_t titles_data_format;                     /* 0x3215 */
    uint8_t acd_index;                              /* 0x3216 */
    uint8_t apparent_platform;                      /* 0x3217 */
    uint8_t _0x3218[0xDE8];                         /* 0x3218 reserved to end */
} nacp_t;
#pragma pack(pop)

void nacp_process(nacp_t *nacp, hactool_ctx_t *tool_ctx);
void nacp_print(nacp_t *nacp, hactool_ctx_t *tool_ctx);
void nacp_save(nacp_t *nacp, hactool_ctx_t *tool_ctx);
char *nacp_get_json(nacp_t *nacp);

#endif
