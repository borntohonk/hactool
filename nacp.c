#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "nacp.h"
#include "utils.h"
#include "settings.h"
#include "cJSON.h"

static const char * const nacp_language_names[18] = {
    "American English",
    "British English",
    "Japanese",
    "French",
    "German",
    "Latin American Spanish",
    "Spanish",
    "Italian",
    "Dutch",
    "Canadian French",
    "Portuguese",
    "Russian",
    "Korean",
    "Traditional Chinese",
    "Simplified Chinese",
    "Brazilian Portuguese",
    "Polish",
    "Thai",
};

static const char * const nacp_rating_org_names[NACP_RATING_ORG_COUNT] = {
    "CERO",
    "GRACGCRB",
    "CLASSIND",
    "USK",
    "ESRB",
    "RLAOA",
    "GENERIC",
    "PEGI",
    "PEGI_PORTUGUESE",
    "PIDVD",
    "MOBAGEAGEREATING",
    "MTTA",
    "COMPUTER_ENTERTAINMENT_RATING_ORGANIZATION",
};

static const char *nacp_startup_user_account_str(uint8_t v) {
    switch (v) {
        case NACP_STARTUP_USER_ACCOUNT_NONE:     return "NONE";
        case NACP_STARTUP_USER_ACCOUNT_REQUIRED: return "REQUIRED";
        case NACP_STARTUP_USER_ACCOUNT_REQUIRED_WITH_NETWORK_SERVICE: return "REQUIRED_WITH_NETWORK_SERVICE_ACCOUNT_AVAILABLE";
        default: return "Unknown";
    }
}

static const char *nacp_user_account_switch_lock_str(uint8_t v) {
    switch (v) {
        case NACP_USER_ACCOUNT_SWITCH_LOCK_DISABLE: return "DISABLE";
        case NACP_USER_ACCOUNT_SWITCH_LOCK_ENABLE:  return "ENABLE";
        default: return "Unknown";
    }
}

static const char *nacp_add_on_content_registration_type_str(uint8_t v) {
    switch (v) {
        case NACP_ADD_ON_CONTENT_REGISTRATION_TYPE_ALL_ON_LAUNCH: return "ALL_ON_LAUNCH";
        case NACP_ADD_ON_CONTENT_REGISTRATION_TYPE_ON_DEMAND:     return "ON_DEMAND";
        default: return "Unknown";
    }
}

static const char *nacp_screenshot_str(uint8_t v) {
    switch (v) {
        case NACP_SCREENSHOT_ALLOW: return "ALLOW";
        case NACP_SCREENSHOT_DENY:  return "DENY";
        default: return "Unknown";
    }
}

static const char *nacp_video_capture_str(uint8_t v) {
    switch (v) {
        case NACP_VIDEO_CAPTURE_DISABLE: return "DISABLE";
        case NACP_VIDEO_CAPTURE_MANUAL:  return "MANUAL";
        case NACP_VIDEO_CAPTURE_ENABLE:  return "ENABLE";
        default: return "Unknown";
    }
}

static const char *nacp_data_loss_confirmation_str(uint8_t v) {
    switch (v) {
        case NACP_DATA_LOSS_CONFIRMATION_NONE:     return "NONE";
        case NACP_DATA_LOSS_CONFIRMATION_REQUIRED: return "REQUIRED";
        default: return "Unknown";
    }
}

static const char *nacp_play_log_policy_str(uint8_t v) {
    switch (v) {
        case NACP_PLAY_LOG_POLICY_OPEN:     return "OPEN";
        case NACP_PLAY_LOG_POLICY_LOG_ONLY: return "LOG_ONLY";
        case NACP_PLAY_LOG_POLICY_NONE:     return "NONE";
        case NACP_PLAY_LOG_POLICY_CLOSED:   return "CLOSED";
        default: return "Unknown";
    }
}

static const char *nacp_logo_type_str(uint8_t v) {
    switch (v) {
        case NACP_LOGO_TYPE_LICENSED_BY_NINTENDO:    return "LICENSED_BY_NINTENDO";
        case NACP_LOGO_TYPE_DISTRIBUTED_BY_NINTENDO: return "DISTRIBUTED_BY_NINTENDO";
        case NACP_LOGO_TYPE_NINTENDO:                return "NINTENDO";
        default: return "Unknown";
    }
}

static const char *nacp_logo_handling_str(uint8_t v) {
    switch (v) {
        case NACP_LOGO_HANDLING_AUTO:   return "AUTO";
        case NACP_LOGO_HANDLING_MANUAL: return "MANUAL";
        default: return "Unknown";
    }
}

static const char *nacp_runtime_add_on_content_install_str(uint8_t v) {
    switch (v) {
        case NACP_RUNTIME_ADD_ON_CONTENT_INSTALL_DENY:                return "DENY";
        case NACP_RUNTIME_ADD_ON_CONTENT_INSTALL_ALLOW_APPEND:        return "ALLOW_APPEND";
        case NACP_RUNTIME_ADD_ON_CONTENT_INSTALL_ALLOW_APPEND_BUT_DONT_DOWNLOAD_ON_NETWORK:
            return "ALLOW_APPEND_BUT_DONT_DOWNLOAD_WHEN_USING_NETWORK";
        default: return "Unknown";
    }
}

static const char *nacp_runtime_parameter_delivery_str(uint8_t v) {
    switch (v) {
        case NACP_RUNTIME_PARAMETER_DELIVERY_ALWAYS:                 return "ALWAYS";
        case NACP_RUNTIME_PARAMETER_DELIVERY_ALWAYS_IF_USER_MATCHED: return "ALWAYS_IF_USER_STATE_MATCHED";
        case NACP_RUNTIME_PARAMETER_DELIVERY_ON_RESTART:             return "ON_RESTART";
        default: return "Unknown";
    }
}

static const char *nacp_appropriate_age_for_china_str(uint8_t v) {
    switch (v) {
        case NACP_APPROPRIATE_AGE_FOR_CHINA_NONE:   return "NONE";
        case NACP_APPROPRIATE_AGE_FOR_CHINA_AGE_8:  return "AGE_8";
        case NACP_APPROPRIATE_AGE_FOR_CHINA_AGE_12: return "AGE_12";
        case NACP_APPROPRIATE_AGE_FOR_CHINA_AGE_16: return "AGE_16";
        default: return "Unknown";
    }
}

static const char *nacp_crash_report_str(uint8_t v) {
    switch (v) {
        case NACP_CRASH_REPORT_DENY:  return "DENY";
        case NACP_CRASH_REPORT_ALLOW: return "ALLOW";
        default: return "Unknown";
    }
}

static const char *nacp_hdcp_str(uint8_t v) {
    switch (v) {
        case NACP_HDCP_NONE:     return "NONE";
        case NACP_HDCP_REQUIRED: return "REQUIRED";
        default: return "Unknown";
    }
}

static const char *nacp_play_log_query_capability_str(uint8_t v) {
    switch (v) {
        case NACP_PLAY_LOG_QUERY_CAPABILITY_NONE:       return "NONE";
        case NACP_PLAY_LOG_QUERY_CAPABILITY_WHITE_LIST: return "WHITE_LIST";
        case NACP_PLAY_LOG_QUERY_CAPABILITY_ALL:        return "ALL";
        default: return "Unknown";
    }
}

static const char *nacp_apparent_platform_str(uint8_t v) {
    switch (v) {
        case NACP_APPARENT_PLATFORM_NX:       return "NX";
        case NACP_APPARENT_PLATFORM_SWITCH_2: return "SWITCH_2";
        default: return "Unknown";
    }
}

void nacp_process(nacp_t *nacp, hactool_ctx_t *tool_ctx) {
    if (tool_ctx->action & ACTION_INFO) {
        nacp_print(nacp, tool_ctx);
    }
    if (tool_ctx->action & ACTION_EXTRACT) {
        nacp_save(nacp, tool_ctx);
    }
}

void nacp_print(nacp_t *nacp, hactool_ctx_t *tool_ctx) {
    (void)tool_ctx;

    printf("[ApplicationControlProperty]\n");

    if (nacp->titles_data_format == NACP_TITLES_DATA_FORMAT_FORMAT1) {
        printf("    TitlesDataFormat:               FORMAT1 (compressed — title names not decoded)\n");
    } else {
        printf("    TitlesDataFormat:               FORMAT0\n");

        int printed_titles = 0;
        for (unsigned int lang = 0; lang < 16; lang++) {
            const nacp_application_title_t *t = &nacp->titles[lang];
            if (t->name[0] != '\0' || t->publisher[0] != '\0') {
                if (!printed_titles) {
                    printf("    Titles:\n");
                    printed_titles = 1;
                }
                const char *lang_name = (lang < 18) ? nacp_language_names[lang] : "Unknown";
                printf("        [%s]\n", lang_name);
                if (t->name[0] != '\0') {
                    printf("            Name:      %.512s\n", t->name);
                }
                if (t->publisher[0] != '\0') {
                    printf("            Publisher: %.256s\n", t->publisher);
                }
            }
        }
    }

    if (nacp->isbn[0] != '\0') {
        printf("    ISBN:                           %.37s\n", nacp->isbn);
    }

    printf("    StartupUserAccount:             %s\n",
           nacp_startup_user_account_str(nacp->startup_user_account));
    printf("    UserAccountSwitchLock:          %s\n",
           nacp_user_account_switch_lock_str(nacp->user_account_switch_lock));
    printf("    AddOnContentRegistrationType:   %s\n",
           nacp_add_on_content_registration_type_str(nacp->add_on_content_registration_type));
    printf("    Screenshot:                     %s\n",
           nacp_screenshot_str(nacp->screenshot));
    printf("    VideoCapture:                   %s\n",
           nacp_video_capture_str(nacp->video_capture));
    printf("    DataLossConfirmation:           %s\n",
           nacp_data_loss_confirmation_str(nacp->data_loss_confirmation));
    printf("    PlayLogPolicy:                  %s\n",
           nacp_play_log_policy_str(nacp->play_log_policy));
    printf("    LogoType:                       %s\n",
           nacp_logo_type_str(nacp->logo_type));
    printf("    LogoHandling:                   %s\n",
           nacp_logo_handling_str(nacp->logo_handling));
    printf("    DisplayVersion:                 %.16s\n", nacp->display_version);
    printf("    PresenceGroupId:                0x%016"PRIx64"\n", nacp->presence_group_id);
    printf("    AddOnContentBaseId:             0x%016"PRIx64"\n", nacp->add_on_content_base_id);
    printf("    SaveDataOwnerId:                0x%016"PRIx64"\n", nacp->save_data_owner_id);
    printf("    LocalCommunicationId:           0x%016"PRIx64"\n", nacp->local_communication_id);

    if (nacp->user_account_save_data_size) {
        printf("    UserAccountSaveDataSize:        0x%"PRIx64"\n",
               nacp->user_account_save_data_size);
    }
    if (nacp->device_save_data_size) {
        printf("    DeviceSaveDataSize:             0x%"PRIx64"\n",
               nacp->device_save_data_size);
    }
    if (nacp->temporary_storage_size) {
        printf("    TemporaryStorageSize:           0x%"PRIx64"\n",
               nacp->temporary_storage_size);
    }
    if (nacp->cache_storage_size) {
        printf("    CacheStorageSize:               0x%"PRIx64"\n",
               nacp->cache_storage_size);
    }

    /* Supported languages from bitmask */
    if (nacp->supported_language_flag) {
        int first = 1;
        for (unsigned int bit = 0; bit < 18; bit++) {
            if (nacp->supported_language_flag & (1u << bit)) {
                if (first) {
                    printf("    SupportedLanguages:             ");
                    first = 0;
                } else {
                    printf(", ");
                }
                printf("%s", nacp_language_names[bit]);
            }
        }
        if (!first) printf("\n");
    }

    /* Rating ages */
    int printed_ratings = 0;
    for (unsigned int org = 0; org < NACP_RATING_ORG_COUNT; org++) {
        uint8_t age = nacp->rating_age[org];
        if (age > 0 && age < 255) {
            if (!printed_ratings) {
                printf("    Ratings:\n");
                printed_ratings = 1;
            }
            printf("        %s: %"PRIu8"\n", nacp_rating_org_names[org], age);
        }
    }

    /* Verbose / extra fields */
    printf("    AttributeFlag:                  0x%08"PRIx32"\n", nacp->attribute_flag);
    printf("    SupportedLanguageFlag:          0x%08"PRIx32"\n", nacp->supported_language_flag);
    printf("    ParentalControlFlag:            0x%08"PRIx32"\n", nacp->parental_control_flag);
    printf("    RuntimeAddOnContentInstall:     %s\n",
           nacp_runtime_add_on_content_install_str(nacp->runtime_add_on_content_install));
    printf("    RuntimeParameterDelivery:       %s\n",
           nacp_runtime_parameter_delivery_str(nacp->runtime_parameter_delivery));
    printf("    AppropriateAgeForChina:         %s\n",
           nacp_appropriate_age_for_china_str(nacp->appropriate_age_for_china));
    printf("    CrashReport:                    %s\n",
           nacp_crash_report_str(nacp->crash_report));
    printf("    Hdcp:                           %s\n",
           nacp_hdcp_str(nacp->hdcp));
    printf("    PlayLogQueryCapability:         %s\n",
           nacp_play_log_query_capability_str(nacp->play_log_query_capability));
    printf("    ApparentPlatform:               %s\n",
           nacp_apparent_platform_str(nacp->apparent_platform));
    if (nacp->bcat_passphrase[0] != '\0') {
        printf("    BcatPassphrase:                 %.16s...\n", nacp->bcat_passphrase);
    }
}

void nacp_save(nacp_t *nacp, hactool_ctx_t *tool_ctx) {
    filepath_t *json_path = &tool_ctx->settings.nacp_json_path;
    if (json_path->valid != VALIDITY_VALID) {
        return;
    }

    FILE *f_json = os_fopen(json_path->os_path, OS_MODE_WRITE);
    if (f_json == NULL) {
        fprintf(stderr, "Failed to open %s!\n", json_path->char_path);
        return;
    }

    char *json = nacp_get_json(nacp);
    if (fwrite(json, 1, strlen(json), f_json) != strlen(json)) {
        fprintf(stderr, "Failed to write NACP JSON file!\n");
        exit(EXIT_FAILURE);
    }
    cJSON_free(json);
    fclose(f_json);
}

char *nacp_get_json(nacp_t *nacp) {
    cJSON *root = cJSON_CreateObject();

    /* TitlesDataFormat */
    cJSON_AddStringToObject(root, "titles_data_format",
        nacp->titles_data_format == NACP_TITLES_DATA_FORMAT_FORMAT1 ? "FORMAT1" : "FORMAT0");

    /* Titles array */
    cJSON *titles_arr = cJSON_CreateArray();
    if (nacp->titles_data_format == NACP_TITLES_DATA_FORMAT_FORMAT0) {
        for (unsigned int lang = 0; lang < 16; lang++) {
            const nacp_application_title_t *t = &nacp->titles[lang];
            if (t->name[0] == '\0' && t->publisher[0] == '\0') continue;
            cJSON *entry = cJSON_CreateObject();
            cJSON_AddStringToObject(entry, "language",
                (lang < 18) ? nacp_language_names[lang] : "Unknown");
            cJSON_AddStringToObject(entry, "name", t->name);
            cJSON_AddStringToObject(entry, "publisher", t->publisher);
            cJSON_AddItemToArray(titles_arr, entry);
        }
    }
    cJSON_AddItemToObject(root, "titles", titles_arr);

    if (nacp->isbn[0] != '\0') {
        char isbn_buf[0x26] = {0};
        strncpy(isbn_buf, nacp->isbn, 0x25);
        cJSON_AddStringToObject(root, "isbn", isbn_buf);
    }

    cJSON_AddStringToObject(root, "startup_user_account",
        nacp_startup_user_account_str(nacp->startup_user_account));
    cJSON_AddStringToObject(root, "user_account_switch_lock",
        nacp_user_account_switch_lock_str(nacp->user_account_switch_lock));
    cJSON_AddStringToObject(root, "add_on_content_registration_type",
        nacp_add_on_content_registration_type_str(nacp->add_on_content_registration_type));
    cJSON_AddStringToObject(root, "screenshot",
        nacp_screenshot_str(nacp->screenshot));
    cJSON_AddStringToObject(root, "video_capture",
        nacp_video_capture_str(nacp->video_capture));
    cJSON_AddStringToObject(root, "data_loss_confirmation",
        nacp_data_loss_confirmation_str(nacp->data_loss_confirmation));
    cJSON_AddStringToObject(root, "play_log_policy",
        nacp_play_log_policy_str(nacp->play_log_policy));
    cJSON_AddStringToObject(root, "logo_type",
        nacp_logo_type_str(nacp->logo_type));
    cJSON_AddStringToObject(root, "logo_handling",
        nacp_logo_handling_str(nacp->logo_handling));

    char disp_ver[0x11] = {0};
    strncpy(disp_ver, nacp->display_version, 0x10);
    cJSON_AddStringToObject(root, "display_version", disp_ver);

    /* Hex u64 fields */
    char buf[0x20];
    snprintf(buf, sizeof(buf), "0x%016"PRIx64, nacp->presence_group_id);
    cJSON_AddStringToObject(root, "presence_group_id", buf);
    snprintf(buf, sizeof(buf), "0x%016"PRIx64, nacp->add_on_content_base_id);
    cJSON_AddStringToObject(root, "add_on_content_base_id", buf);
    snprintf(buf, sizeof(buf), "0x%016"PRIx64, nacp->save_data_owner_id);
    cJSON_AddStringToObject(root, "save_data_owner_id", buf);
    snprintf(buf, sizeof(buf), "0x%016"PRIx64, nacp->local_communication_id);
    cJSON_AddStringToObject(root, "local_communication_id", buf);

    /* Save data sizes */
    cJSON_AddNumberToObject(root, "user_account_save_data_size",
        (double)nacp->user_account_save_data_size);
    cJSON_AddNumberToObject(root, "user_account_save_data_journal_size",
        (double)nacp->user_account_save_data_journal_size);
    cJSON_AddNumberToObject(root, "device_save_data_size",
        (double)nacp->device_save_data_size);
    cJSON_AddNumberToObject(root, "device_save_data_journal_size",
        (double)nacp->device_save_data_journal_size);
    cJSON_AddNumberToObject(root, "bcat_delivery_cache_storage_size",
        (double)nacp->bcat_delivery_cache_storage_size);
    cJSON_AddNumberToObject(root, "temporary_storage_size",
        (double)nacp->temporary_storage_size);
    cJSON_AddNumberToObject(root, "cache_storage_size",
        (double)nacp->cache_storage_size);
    cJSON_AddNumberToObject(root, "cache_storage_journal_size",
        (double)nacp->cache_storage_journal_size);
    cJSON_AddNumberToObject(root, "cache_storage_data_and_journal_size_max",
        (double)nacp->cache_storage_data_and_journal_size_max);
    cJSON_AddNumberToObject(root, "cache_storage_index_max",
        (double)nacp->cache_storage_index_max);

    /* Flags */
    snprintf(buf, sizeof(buf), "0x%08"PRIx32, nacp->attribute_flag);
    cJSON_AddStringToObject(root, "attribute_flag", buf);
    snprintf(buf, sizeof(buf), "0x%08"PRIx32, nacp->supported_language_flag);
    cJSON_AddStringToObject(root, "supported_language_flag", buf);
    snprintf(buf, sizeof(buf), "0x%08"PRIx32, nacp->parental_control_flag);
    cJSON_AddStringToObject(root, "parental_control_flag", buf);

    /* Supported language names array */
    cJSON *lang_arr = cJSON_CreateArray();
    for (unsigned int bit = 0; bit < 18; bit++) {
        if (nacp->supported_language_flag & (1u << bit)) {
            cJSON_AddItemToArray(lang_arr, cJSON_CreateString(nacp_language_names[bit]));
        }
    }
    cJSON_AddItemToObject(root, "supported_languages", lang_arr);

    /* Rating ages */
    cJSON *ratings_obj = cJSON_CreateObject();
    for (unsigned int org = 0; org < NACP_RATING_ORG_COUNT; org++) {
        uint8_t age = nacp->rating_age[org];
        if (age > 0 && age < 255) {
            cJSON_AddNumberToObject(ratings_obj, nacp_rating_org_names[org], age);
        }
    }
    cJSON_AddItemToObject(root, "rating_ages", ratings_obj);

    /* Runtime and misc */
    cJSON_AddStringToObject(root, "runtime_add_on_content_install",
        nacp_runtime_add_on_content_install_str(nacp->runtime_add_on_content_install));
    cJSON_AddStringToObject(root, "runtime_parameter_delivery",
        nacp_runtime_parameter_delivery_str(nacp->runtime_parameter_delivery));
    cJSON_AddStringToObject(root, "appropriate_age_for_china",
        nacp_appropriate_age_for_china_str(nacp->appropriate_age_for_china));
    cJSON_AddStringToObject(root, "crash_report",
        nacp_crash_report_str(nacp->crash_report));
    cJSON_AddStringToObject(root, "hdcp",
        nacp_hdcp_str(nacp->hdcp));
    cJSON_AddStringToObject(root, "play_log_query_capability",
        nacp_play_log_query_capability_str(nacp->play_log_query_capability));
    cJSON_AddStringToObject(root, "apparent_platform",
        nacp_apparent_platform_str(nacp->apparent_platform));

    cJSON_AddNumberToObject(root, "program_index", nacp->program_index);
    cJSON_AddNumberToObject(root, "repair_flag", nacp->repair_flag);
    cJSON_AddNumberToObject(root, "runtime_upgrade", nacp->runtime_upgrade);
    cJSON_AddNumberToObject(root, "startup_user_account_option",
        nacp->startup_user_account_option);
    cJSON_AddNumberToObject(root, "required_network_service_license_on_launch_flag",
        nacp->required_network_service_license_on_launch_flag);
    cJSON_AddNumberToObject(root, "application_error_code_prefix",
        nacp->application_error_code_prefix);
    cJSON_AddNumberToObject(root, "acd_index", nacp->acd_index);

    if (nacp->bcat_passphrase[0] != '\0') {
        char pp_buf[0x42] = {0};
        strncpy(pp_buf, nacp->bcat_passphrase, 0x41);
        cJSON_AddStringToObject(root, "bcat_passphrase", pp_buf);
    }

    /* Play-log queryable application IDs (non-zero entries only) */
    cJSON *plog_arr = cJSON_CreateArray();
    for (unsigned int i = 0; i < 16; i++) {
        if (nacp->play_log_queryable_application_ids[i] != 0) {
            snprintf(buf, sizeof(buf), "0x%016"PRIx64,
                     nacp->play_log_queryable_application_ids[i]);
            cJSON_AddItemToArray(plog_arr, cJSON_CreateString(buf));
        }
    }
    cJSON_AddItemToObject(root, "play_log_queryable_application_ids", plog_arr);

    char *out = cJSON_Print(root);
    cJSON_Delete(root);
    return out;
}
