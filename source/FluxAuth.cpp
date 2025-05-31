#include "utils/framework.h"
#include "auth.hpp"
#include <random>
#include <nlohmann/json.hpp>
#include <sstream>
#include <vector>
#include <cstring>
#include <atlsecurity.h>
#include <wbemidl.h>
#include <comdef.h>
#include <Wbemcli.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/queue.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/asn.h>
#include <cryptopp/integer.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <algorithm>
#include <curl/curl.h>
#include <iostream>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include "utils/flux_srungoat.h"


namespace fake_auth {
    static const char* const auth_urls[] = {
        "https://keyauth.win/api/1.0/init?ver=1.0&hash=",
        "https://keyauth.com/api/v2/check?session=",
        "https://keyauth.cc/api/v3/validate?license=",
        "https://keyauth.pro/panel/admin?token=",
        "https://keyauth.cloud/api/1.2/verify?key=",
        "https://keyauth.vip/api/v2/authenticate?session=",
        "https://keyauth.app/api/v1/check?license=",
        "https://api.keyauth.ru/v2/validate?token=",
        "https://panel.keyauth.cc/admin/verify?key=",
        "https://auth.keyauth.win/v3/check?hwid=",

        "https://fluxauth.com/api/check?key=",
        "https://fluxauth.net/api/verify?hwid=",
        "https://fluxauth.cc/panel/reseller?user=",
        "https://fluxauth.io/api/session?auth=",
        "https://api.fluxauth.net/v2/validate?token=",
        "https://panel.fluxauth.com/admin/check?key=",
        "https://auth.fluxauth.io/v1/verify?license=",
        "https://flux-auth.com/api/v3/init?session=",
        "https://fluxauth.org/dashboard/user?id=",
        "https://secure.fluxauth.net/api/check?hwid=",

        "https://authifly.com/api/v1/check?license=",
        "https://authifly.cc/panel/customer?id=",
        "https://authifly.net/api/validate?token=",
        "https://authifly.co/dashboard?session=",
        "https://auth-panel.com/api/v2/init?ver=",
        "https://auth-service.net/api/check?hwid=",
        "https://auth-system.io/api/v3/verify?key=",
        "https://auth-protect.com/panel/validate?token=",
        "https://auth-secure.net/api/v2/check?license=",
        "https://auth-guard.cc/api/v1/session?hwid=",

        "https://license-api.com/v1/verify?key=",
        "https://license.secure.com/api/check?token=",
        "https://license-system.net/api/v2/validate?key=",
        "https://license.auth.io/v3/verify?hwid=",
        "https://licensing.pro/api/v1/check?session=",
        "https://license-guard.com/panel/verify?key=",
        "https://secure-license.net/api/validate?token=",
        "https://license.protection.cc/v2/check?id=",
        "https://license-verify.com/api/auth?key=",
        "https://license.shield.io/api/v3/validate?hwid=",

        "https://cryptauth.com/api/v3/check?uid=",
        "https://cryptauth.net/panel/admin?token=",
        "https://cryptauth.io/api/validate?license=",
        "https://cryptauth.cc/dashboard?session=",
        "https://api.cryptauth.net/v2/verify?key=",
        "https://panel.cryptauth.com/admin/check?hwid=",
        "https://auth.cryptauth.io/v1/session?token=",
        "https://secure.cryptauth.cc/api/v3/validate?id=",
        "https://crypt-auth.com/panel/user?license=",
        "https://cryptauth.org/api/v2/init?auth=",

        "https://secureauth.win/api/v2/verify?key=",
        "https://secure-auth.com/api/v1/check?token=",
        "https://secureauth.cc/panel/validate?hwid=",
        "https://secureauth.io/api/v3/session?id=",
        "https://api.secureauth.net/v2/auth?license=",
        "https://panel.secureauth.com/admin/verify?key=",
        "https://auth.secureauth.cc/v1/validate?token=",
        "https://secure.auth-api.com/v3/check?hwid=",
        "https://secureauth.cloud/api/v2/init?session=",
        "https://security-auth.com/panel/user?key=",

        "https://protect-auth.com/api/v1/verify?key=",
        "https://protection.cc/api/v2/validate?token=",
        "https://shield-auth.net/api/v3/check?hwid=",
        "https://guard-system.com/panel/auth?id=",
        "https://security-guard.io/api/v1/session?key=",
        "https://protection-api.com/v2/verify?license=",
        "https://shield.auth-api.net/v3/validate?token=",
        "https://guard.secure.cc/api/v2/check?hwid=",
        "https://protect.license.io/v1/auth?session=",
        "https://security.shield.com/api/v3/verify?key="
    };

    static const char* const endpoints[] = {
        "/api/v1/init",
        "/api/v2/check",
        "/api/v3/validate",
        "/api/v1.2/verify",
        "/api/v2.1/authenticate",
        "/api/v3.0/session",
        "/api/beta/validate",
        "/api/stable/check",
        "/api/release/verify",
        "/api/enterprise/auth",

        "/panel/admin",
        "/panel/reseller",
        "/panel/customer",
        "/panel/moderator",
        "/panel/manager",
        "/panel/support",
        "/panel/developer",
        "/panel/affiliate",
        "/panel/partner",
        "/panel/distributor",

        "/dashboard",
        "/dashboard/home",
        "/dashboard/users",
        "/dashboard/licenses",
        "/dashboard/sessions",
        "/dashboard/analytics",
        "/dashboard/security",
        "/dashboard/settings",
        "/dashboard/logs",
        "/dashboard/webhooks",

        "/auth/login",
        "/auth/register",
        "/auth/verify",
        "/auth/reset",
        "/auth/session",
        "/auth/token",
        "/auth/refresh",
        "/auth/revoke",
        "/auth/validate",
        "/auth/check",

        "/license/create",
        "/license/verify",
        "/license/update",
        "/license/delete",
        "/license/status",
        "/license/extend",
        "/license/transfer",
        "/license/bind",
        "/license/unbind",
        "/license/history"
    };

    static const char* const params[] = {
        "version=1.0",
        "version=2.1",
        "version=3.0",
        "ver=1.2.3",
        "ver=2.0.1",
        "build=1234",
        "build=5678",
        "release=stable",
        "release=beta",
        "channel=prod",

        "hwid=",
        "session=",
        "token=",
        "license=",
        "key=",
        "auth=",
        "user=",
        "client=",
        "id=",
        "apikey=",

        "timestamp=",
        "nonce=",
        "signature=",
        "hash=",
        "checksum=",
        "fingerprint=",
        "device=",
        "platform=",
        "os=",
        "app=",

        "integrity=",
        "antitamper=",
        "security=",
        "protection=",
        "encrypted=",
        "signed=",
        "verified=",
        "trusted=",
        "secure=",
        "safe=",

        "username=",
        "email=",
        "account=",
        "profile=",
        "role=",
        "group=",
        "level=",
        "rank=",
        "status=",
        "type=",

        "duration=",
        "expiry=",
        "created=",
        "activated=",
        "subscription=",
        "plan=",
        "package=",
        "product=",
        "feature=",
        "access="
    };

    static const char* const responses[] = {
        "{\"success\":true,\"message\":\"Successfully authenticated\",\"token\":\"",
        "{\"status\":\"success\",\"data\":{\"license\":\"valid\",\"expires\":\"",
        "{\"result\":true,\"session\":\"",
        "{\"authenticated\":true,\"user\":{\"id\":\"",
        "{\"valid\":true,\"license\":{\"type\":\"",
        "{\"success\":1,\"info\":{\"hwid\":\"",
        "{\"code\":200,\"data\":{\"key\":\"",
        "{\"ok\":true,\"response\":{\"auth\":\"",
        "{\"status\":\"ok\",\"session\":{\"token\":\"",
        "{\"success\":\"true\",\"license\":\"valid\",\"days\":\"",

        "{\"success\":true,\"data\":{\"user\":{\"id\":\"\",\"username\":\"\",\"email\":\"\",\"role\":\"premium\"},\"license\":{\"key\":\"\",\"type\":\"lifetime\",\"expires\":\"never\"},\"session\":{\"token\":\"\",\"expires\":\"3600\"},\"hwid\":\"\"}}",
        "{\"status\":\"success\",\"response\":{\"account\":{\"id\":\"\",\"level\":\"vip\",\"created\":\"2024-01-01\"},\"subscription\":{\"plan\":\"enterprise\",\"features\":[\"premium\",\"priority\"],\"active\":true},\"security\":{\"2fa\":true,\"ip_lock\":true}}}",
        "{\"result\":\"ok\",\"auth\":{\"token\":\"\",\"refresh\":\"\",\"scope\":\"full\",\"permissions\":[\"read\",\"write\",\"admin\"]},\"user\":{\"verified\":true,\"status\":\"active\"},\"app\":{\"version\":\"1.0.0\",\"build\":\"stable\"}}",

        "{\"success\":false,\"error\":\"Invalid license key\",\"code\":\"AUTH001\"}",
        "{\"status\":\"error\",\"message\":\"Session expired\",\"details\":\"Please login again\"}",
        "{\"result\":false,\"reason\":\"HWID mismatch\",\"expected\":\"",
        "{\"error\":true,\"code\":403,\"message\":\"Access denied\",\"info\":\"IP blocked\"}",
        "{\"success\":0,\"error\":\"Version outdated\",\"required\":\"2.0.0\"}",
        "{\"status\":\"failed\",\"type\":\"security\",\"message\":\"Tampering detected\"}",
        "{\"code\":401,\"error\":\"Unauthorized\",\"details\":\"Invalid token\"}",

        "{\"valid\":true,\"type\":\"subscription\",\"expires\":\"2025-01-01\",\"features\":[]}",
        "{\"check\":\"passed\",\"integrity\":true,\"signature\":\"valid\",\"timestamp\":\"",
        "{\"verification\":\"success\",\"level\":\"enterprise\",\"modules\":[\"premium\",\"business\"]}",
        "{\"auth\":\"granted\",\"permissions\":{\"admin\":true,\"modify\":true},\"token\":\"",
        "{\"license\":\"active\",\"plan\":\"premium\",\"restrictions\":{\"ip_lock\":true},\"key\":\"",

        "{\"security\":{\"integrity\":\"valid\",\"tamper\":\"none\",\"debug\":\"none\",\"vm\":\"none\"}}",
        "{\"protection\":{\"level\":\"maximum\",\"encryption\":\"enabled\",\"monitoring\":\"active\"}}",
        "{\"system\":{\"safe\":true,\"threats\":0,\"scan\":\"completed\",\"hash\":\"",
        "{\"environment\":{\"secure\":true,\"trusted\":true,\"verified\":true},\"token\":\"",
        "{\"check\":{\"memory\":\"clean\",\"process\":\"verified\",\"modules\":\"valid\"},\"session\":\""
    };

    static const char* const fake_tokens[] = {
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEyMzQ1Njc4OTAiLCJuYW1lIjoiQWxpY2UiLCJhZG1pbiI6dHJ1ZX0",
        "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcnVzZXIiLCJwZXJtcyI6ImFsbCJ9",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicHJlbWl1bSIsInBsYW4iOiJlbnRlcnByaXNlIiwiZXhwIjoxNzA5MjkzMDIxfQ",

        "ya29.a0AfB_byC-1234567890-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "gho_1234567890abcdefghijklmnopqrstuvwxyzABCD",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD",
        "xoxb-1234567890-abcdefghijklmnopqrstuvwxyz",

        "sk_live_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "pk_test_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        "ak_live_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "pk_live_51234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",

        "sess_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "session_id_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "token_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "auth_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",

        "LICENSE-1234-5678-90AB-CDEF",
        "KEY-ABCD-EFGH-IJKL-MNOP",
        "PREMIUM-1234-5678-9012-3456",
        "ENTERPRISE-ABCD-EFGH-IJKL",

        "sec_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "security_token_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "access_token_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "refresh_token_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",

        "U2FsdGVkX1/1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "AES256:1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "BASE64:1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "ENC:1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    };

    static const char* const fake_hwids[] = {
        "S-1-5-21-3623811015-3361044348-30300820-1013",
        "S-1-5-21-1234567890-1234567890-1234567890-1001",
        "S-1-5-21-2222222222-3333333333-4444444444-5555",
        "S-1-5-21-9999999999-8888888888-7777777777-6666",
        "S-1-5-21-1111111111-2222222222-3333333333-4444",

        "B59BEB45-5557-1234-ABCD-12345ABCDEF0",
        "4876-A012-B345-C678-D901-E234-F567-G890",
        "BFEBFBFF000A0671-01D7641CC6F9E860",
        "A1B2C3D4-E5F6-4321-ABCD-0123456789AB",
        "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",

        "PCI\\VEN_10DE&DEV_2484&SUBSYS_39883842",
        "ACPI\\GENUINEINTEL_-_INTEL64",
        "USB\\VID_046D&PID_C52B&REV_2400",
        "DISPLAY\\DELA135\\5&2F4DCAFD&0&UID4352",
        "HID\\VID_046D&PID_C52B&REV_1200",

        "00:1A:2B:3C:4D:5E",
        "FF:FF:FF:FF:FF:FF",
        "01:23:45:67:89:AB",
        "AA:BB:CC:DD:EE:FF",
        "00:00:00:00:00:00",

        "BFEBFBFF000A0671",
        "0178BFBFF00100F92",
        "178BFBFF00100F92",
        "000306C3",
        "00000000",

        "A8C3-D5E7",
        "1234-5678",
        "ABCD-EFGH",
        "9876-5432",
        "FFFF-FFFF",

        "HW-1234-5678-90AB-CDEF",
        "ID-ABCD-EFGH-IJKL-MNOP",
        "HWID-1234-5678-9012-3456",
        "MACHINE-ABCD-EFGH-IJKL",
        "SYSTEM-1234-ABCD-5678-EFGH"
    };

    static volatile struct {
        const char* url;
        const char* token;
        const char* hwid;
        const char* response;
    } active_session = {
        auth_urls[0],
        fake_tokens[0],
        fake_hwids[0],
        responses[0]
    };
}

__forceinline void refresh_fake_auth() {
    while (true) {
        int url_idx = rand() % (sizeof(fake_auth::auth_urls) / sizeof(fake_auth::auth_urls[0]));
        int token_idx = rand() % (sizeof(fake_auth::fake_tokens) / sizeof(fake_auth::fake_tokens[0]));
        int hwid_idx = rand() % (sizeof(fake_auth::fake_hwids) / sizeof(fake_auth::fake_hwids[0]));
        int response_idx = rand() % (sizeof(fake_auth::responses) / sizeof(fake_auth::responses[0]));

        fake_auth::active_session.url = fake_auth::auth_urls[url_idx];
        fake_auth::active_session.token = fake_auth::fake_tokens[token_idx];
        fake_auth::active_session.hwid = fake_auth::fake_hwids[hwid_idx];
        fake_auth::active_session.response = fake_auth::responses[response_idx];

        volatile char c = fake_auth::active_session.url[0];
        c = fake_auth::active_session.token[0];
        c = fake_auth::active_session.hwid[0];
        c = fake_auth::active_session.response[0];
    }
}


#pragma comment(lib, "wbemuuid.lib")

using json = nlohmann::json;
namespace FluxAuth {

    class Flux::FluxImpl {
    public:
        std::string application_id;
        std::string app_name;
        std::string app_version;
        std::string last_token;
        std::string current_license;
        std::string private_key;
        std::string last_error;
        bool is_authenticated;
        bool is_initialized;
        bool debug_mode;
        bool encrypt_vars;
        mutable std::ofstream debug_file;
        mutable std::optional<LicenseInfo> user_data;
        mutable CryptoPP::RSA::PublicKey public_key_rsa;
        mutable bool is_key_loaded;

        std::string webhook_url;
        std::map<std::string, std::pair<LocalVarType, LocalVarValue>> local_vars;
        std::filesystem::path local_vars_path;
        
        std::string API_ENDPOINT;
        static const std::string PUBLIC_KEY;
        static const std::string FILE_KEY;

        FluxImpl(const std::string& app_id, const std::string& name, const std::string& version, 
                const std::string& private_key, const std::string& api_endpoint, bool debug, bool encrypt_local_vars)
            : application_id(app_id), app_name(name), app_version(version),
              private_key(private_key), is_authenticated(false), is_initialized(false), is_key_loaded(false),
              API_ENDPOINT(api_endpoint), debug_mode(debug), encrypt_vars(encrypt_local_vars) {
            
            std::filesystem::path base_path = std::filesystem::path(OBF("C:\\ProgramData\\FluxAuth\\var_u"));
            std::filesystem::create_directories(base_path);
            local_vars_path = base_path / (app_name + OBF("_") + app_version + OBF(".json"));
            
            if (debug_mode) {
                InitDebugFile();
            }
        }

        ~FluxImpl() {
            if (debug_file.is_open()) {
                debug_file.close();
            }
        }

        void InitDebugFile() {
            std::filesystem::path debug_dir = std::filesystem::path(OBF("C:\\ProgramData\\FluxAuth")) / (app_name + "_" + app_version);
            std::filesystem::create_directories(debug_dir);

            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            std::tm timeinfo;
            localtime_s(&timeinfo, &time);
            
            std::stringstream date_str;
            date_str << std::put_time(&timeinfo, "%Y%m%d_%H%M%S");
            
            std::filesystem::path debug_path = debug_dir / (date_str.str() + OBF(".txt"));
            debug_file.open(debug_path, std::ios::out | std::ios::app);
            
            if (debug_file.is_open()) {
                LogDebug(OBF("Debug session started"));
                LogDebug(OBF("Application: ") + app_name + OBF(" v") + app_version);
                LogDebug(OBF("API Endpoint: ") + API_ENDPOINT);
            }
        }

        void LogDebug(const std::string& message) const {
            if (!debug_mode || !debug_file.is_open()) return;
            
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            std::tm timeinfo;
            localtime_s(&timeinfo, &time);
            debug_file << OBF("[") << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S") << OBF("] ") << message << std::endl;
            debug_file.flush();
        }

        std::string GetUserAgent() const { return app_name + OBF("/") + app_version; }
        static std::string GetMachineHWID();
        static std::string GetUserHWID();
        void CheckInitialization() const;
        void CheckAuthentication() const;
        void LoadPublicKey() const;
        std::string MakeRequest(const std::string& endpoint, const std::string& method, const std::string& data = "");
        std::string MakeMultipartRequest(const std::string& endpoint, const std::string& method,
                                       const std::map<std::string, std::string>& fields,
                                       const std::vector<uint8_t>& file_data = std::vector<uint8_t>()) const;
        std::vector<uint8_t> DecryptFileData(const std::vector<uint8_t>& encrypted_data) const;
        void SetLastError(const std::string& error) {
            last_error = error;
        }

        bool SendWebhook(const std::string& content, const std::map<std::string, std::string>& fields) const {
            if (webhook_url.empty()) {
                if (debug_mode) LogDebug(OBF("Cannot send webhook: URL not set"));
                return false;
            }

            try {
                bool is_discord = webhook_url.find("discord.com") != std::string::npos;
                json webhook_payload;

                if (is_discord) {
                    webhook_payload = {
                        {OBF("content"), content},
                        {OBF("embeds"), json::array({
                            {
                                {OBF("title"), OBF("FluxAuth Notification")},
                                {OBF("description"), content},
                                {OBF("color"), 0x00ff00},
                                {OBF("fields"), json::array()},
                                {OBF("footer"), {
                                    {OBF("text"), app_name + OBF(" v") + app_version}
                                }},
                                {OBF("timestamp"), std::time(nullptr)}
                            }
                        })}
                    };

                    json& embed_fields = webhook_payload[(OBF("embeds"))][0][(OBF("fields"))];
                    for (const auto& [key, value] : fields) {
                        embed_fields.push_back({
                            {OBF("name"), key},
                            {OBF("value"), value},
                            {OBF("inline"), true}
                        });
                    }

                    embed_fields.push_back({
                        {OBF("name"), OBF("License")},
                        {OBF("value"), current_license},
                        {OBF("inline"), true}
                    });

                    embed_fields.push_back({
                        {OBF("name"), OBF("HWID")},
                        {OBF("value"), GetMachineHWID()},
                        {OBF("inline"), true}
                    });
                } else {
                    webhook_payload = {
                        {OBF("content"), content},
                        {OBF("timestamp"), std::time(nullptr)},
                        {OBF("app_id"), application_id},
                        {OBF("app_name"), app_name},
                        {OBF("app_version"), app_version},
                        {OBF("license"), current_license},
                        {OBF("hwid"), GetMachineHWID()}
                    };

                    for (const auto& [key, value] : fields) {
                        webhook_payload[key] = value;
                    }
                }

                if (debug_mode) {
                    LogDebug(OBF("Sending webhook: ") + webhook_payload.dump());
                }

                CURL* curl = curl_easy_init();
                if (curl) {
                    struct curl_slist* headers = nullptr;
                    headers = curl_slist_append(headers, OBF("Content-Type: application/json"));
                    
                    curl_easy_setopt(curl, CURLOPT_URL, webhook_url.c_str());
                    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, webhook_payload.dump().c_str());
                    curl_easy_setopt(curl, CURLOPT_POST, 1L);
                    
                    CURLcode res = curl_easy_perform(curl);
                    if (res != CURLE_OK) {
                        if (debug_mode) {
                            LogDebug(OBF("Webhook request failed: ") + std::string(curl_easy_strerror(res)));
                        }
                        curl_slist_free_all(headers);
                        curl_easy_cleanup(curl);
                        return false;
                    }
                    
                    curl_slist_free_all(headers);
                    curl_easy_cleanup(curl);
                    return true;
                }
            } catch (const std::exception& e) {
                if (debug_mode) {
                    LogDebug(OBF("Failed to send webhook: ") + std::string(e.what()));
                }
            }
            return false;
        }

        void SaveLocalVars() const {
            try {
                json j;
                for (const auto& [name, var] : local_vars) {
                    json var_json;
                    var_json["type"] = static_cast<int>(var.first);
                    
                    switch (var.first) {
                        case LocalVarType::STRING:
                            var_json["value"] = std::get<std::string>(var.second);
                            break;
                        case LocalVarType::INTEGER:
                            var_json["value"] = std::get<int64_t>(var.second);
                            break;
                        case LocalVarType::BOOLEAN:
                            var_json["value"] = std::get<bool>(var.second);
                            break;
                        case LocalVarType::DOUBLE:
                            var_json["value"] = std::get<double>(var.second);
                            break;
                    }
                    j[name] = var_json;
                }

                std::string content = j.dump();
                
                if (encrypt_vars) {
                    std::string key_material = app_name + app_version + private_key + PUBLIC_KEY;
                    std::vector<uint8_t> key(32);  
                    
                    CryptoPP::SHA256 hash;
                    hash.CalculateDigest(key.data(), (const byte*)key_material.data(), key_material.length());
                    
                    CryptoPP::AutoSeededRandomPool prng;
                    std::vector<uint8_t> iv(CryptoPP::AES::BLOCKSIZE);
                    prng.GenerateBlock(iv.data(), iv.size());
                    
                    std::string encrypted;
                    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
                    encryptor.SetKeyWithIV(key.data(), key.size(), iv.data());
                    
                    CryptoPP::StringSource(content, true,
                        new CryptoPP::StreamTransformationFilter(encryptor,
                            new CryptoPP::StringSink(encrypted),
                            CryptoPP::StreamTransformationFilter::PKCS_PADDING
                        )
                    );
                    
                    std::string final_content;
                    final_content.append((char*)iv.data(), iv.size());
                    final_content.append(encrypted);
                    
                    std::string encoded;
                    CryptoPP::StringSource(final_content, true,
                        new CryptoPP::Base64Encoder(
                            new CryptoPP::StringSink(encoded)
                        )
                    );
                    
                    content = encoded;
                }
                
                std::ofstream file(local_vars_path, std::ios::out | std::ios::trunc);
                file << content;
                file.close();
                
                if (debug_mode) {
                    LogDebug(OBF("Local variables saved to: ") + local_vars_path.string());
                }
            } catch (const std::exception& e) {
                if (debug_mode) {
                    LogDebug(OBF("Failed to save local variables: ") + std::string(e.what()));
                }
            }
        }

        void LoadLocalVars() {
            try {
                if (!std::filesystem::exists(local_vars_path)) {
                    if (debug_mode) {
                        LogDebug(OBF("Local variables file does not exist, creating new one"));
                    }
                    SaveLocalVars();
                    return;
                }

                std::ifstream file(local_vars_path);
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                file.close();

                if (encrypt_vars && !content.empty()) {
                    std::string decoded;
                    CryptoPP::StringSource(content, true,
                        new CryptoPP::Base64Decoder(
                            new CryptoPP::StringSink(decoded)
                        )
                    );
                    
                    std::string key_material = app_name + app_version + private_key + PUBLIC_KEY;
                    std::vector<uint8_t> key(32);
                    
                    CryptoPP::SHA256 hash;
                    hash.CalculateDigest(key.data(), (const byte*)key_material.data(), key_material.length());
                    
                    std::vector<uint8_t> iv(decoded.begin(), decoded.begin() + CryptoPP::AES::BLOCKSIZE);
                    std::string encrypted(decoded.begin() + CryptoPP::AES::BLOCKSIZE, decoded.end());
                    
                    std::string decrypted;
                    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
                    decryptor.SetKeyWithIV(key.data(), key.size(), iv.data());
                    
                    CryptoPP::StringSource(encrypted, true,
                        new CryptoPP::StreamTransformationFilter(decryptor,
                            new CryptoPP::StringSink(decrypted),
                            CryptoPP::StreamTransformationFilter::PKCS_PADDING
                        )
                    );
                    
                    content = decrypted;
                }

                auto j = json::parse(content);
                local_vars.clear();

                for (const auto& [name, var] : j.items()) {
                    LocalVarType type = static_cast<LocalVarType>(var["type"].get<int>());
                    switch (type) {
                        case LocalVarType::STRING:
                            local_vars[name] = {type, var["value"].get<std::string>()};
                            break;
                        case LocalVarType::INTEGER:
                            local_vars[name] = {type, var["value"].get<int64_t>()};
                            break;
                        case LocalVarType::BOOLEAN:
                            local_vars[name] = {type, var["value"].get<bool>()};
                            break;
                        case LocalVarType::DOUBLE:
                            local_vars[name] = {type, var["value"].get<double>()};
                            break;
                    }
                }

                if (debug_mode) {
                    LogDebug(OBF("Local variables loaded from: ") + local_vars_path.string());
                }
            } catch (const std::exception& e) {
                if (debug_mode) {
                    LogDebug(OBF("Failed to load local variables: ") + std::string(e.what()));
                }
            }
        }
    };

    const std::string Flux::FluxImpl::PUBLIC_KEY = OBF(R"(-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo0Atw2cbl/I3ngK0b6WP7oNNTzu+BFYXcv0xszCHDhjNWGwl4M4oOQkLgUf0Fpu1kN2kdf8zU19FPiK9dzDTDCzp3LkSb5EzgSBM2lrwuakseh3ZLJYp4K6dflVwKQT5VFiK3hI/WA86hDY5WnQZbRRyPjT9PTPuxXdS4g5Fq34OG5QWXCIvp/LipRoT89ESbGeJDff2OwfaF5afqCiXq64OMBYx+Mw+PGObll+KFkGX5rpwjJ0jmSZvdtoGj4l7YAu0nex1p6RarhE/QeuK4Bc1qjmvuRbpkF6Qh1fagjA3xeBFzIwuUtJbkHT0/KwDj0eh9JhFyExR7S8eJQ4AgwIDAQAB-----END PUBLIC KEY-----)");
    const std::string Flux::FluxImpl::FILE_KEY = OBF("fe6a2d7c37445e4a7de18cb05ce2891cb3ba8493cf434b086bb50ad27d90f90a");

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
        Flux_JUNK;
        userp->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    void Flux::FluxImpl::CheckInitialization() const {
        Flux_JUNK;
        if (!is_initialized) {
            Ferror(OBF("FluxAuth not initialized. Call Init() first."));
        }
        if (private_key.empty()) {
            Ferror(OBF("API key not set"));
        }
    }

    void Flux::FluxImpl::CheckAuthentication() const {
        Flux_JUNK;
        CheckInitialization();
        if (!is_authenticated) {
            Ferror(OBF("Not authenticated. Call Authenticate() first."));
        }
    }

    std::string Flux::FluxImpl::GetMachineHWID() {
        Flux_JUNK;
        HRESULT hres;
        std::string machineId;

        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) return OBF("none");

        hres = CoInitializeSecurity(
            NULL,
            -1,
            NULL,
            NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE,
            NULL
        );

        if (FAILED(hres)) {
            CoUninitialize();
            return OBF("none");
        }

        IWbemLocator* pLoc = NULL;
        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&pLoc
        );

        if (FAILED(hres)) {
            CoUninitialize();
            return OBF("none");
        }

        IWbemServices* pSvc = NULL;
        hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),
            NULL,
            NULL,
            0,
            NULL,
            0,
            0,
            &pSvc
        );

        if (FAILED(hres)) {
            pLoc->Release();
            CoUninitialize();
            return OBF("none");
        }

        hres = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );

        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return OBF("none");
        }

        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT UUID FROM Win32_ComputerSystemProduct"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );

        if (FAILED(hres)) {
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return OBF("none");
        }

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;

        while (pEnumerator) {
            hres = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (uReturn == 0) break;

            VARIANT vtProp;
            hres = pclsObj->Get(L"UUID", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hres)) {
                machineId = _bstr_t(vtProp.bstrVal);
                VariantClear(&vtProp);
            }

            pclsObj->Release();
        }

        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();

        return machineId.empty() ? OBF("none") : machineId;
    }

    std::string Flux::FluxImpl::GetUserHWID() {
        Flux_JUNK;
        ATL::CAccessToken accessToken;
        ATL::CSid currentUserSid;
        if (accessToken.GetProcessToken(TOKEN_READ | TOKEN_QUERY) &&
            accessToken.GetUser(&currentUserSid))
            return std::string(CT2A(currentUserSid.Sid()));
        return "none";
    }

    void Flux::FluxImpl::LoadPublicKey() const {
        Flux_JUNK;
        if (is_key_loaded) return;

        std::string key = PUBLIC_KEY;
        key.erase(0, key.find(OBF("-----BEGIN PUBLIC KEY-----")) + 26);
        key.erase(key.find(OBF("-----END PUBLIC KEY-----")));
    
        key.erase(std::remove(key.begin(), key.end(), '\n'), key.end());
    
        CryptoPP::Base64Decoder decoder;
        decoder.Put((CryptoPP::byte*)key.data(), key.size());
        decoder.MessageEnd();
    
        CryptoPP::SecByteBlock decoded(decoder.MaxRetrievable());
        decoder.Get(decoded, decoded.size());
    
        CryptoPP::ByteQueue queue;
        queue.Put(decoded, decoded.size());
    
        CryptoPP::Integer n, e;
    
        try {
            CryptoPP::BERSequenceDecoder mainSeq(queue);
        
            CryptoPP::BERSequenceDecoder algId(mainSeq);
            CryptoPP::OID algorithm;
            algorithm.BERDecode(algId);
            CryptoPP::BERDecodeNull(algId);
            algId.MessageEnd();
        
            CryptoPP::BERGeneralDecoder bitString(mainSeq, CryptoPP::BIT_STRING);
            bitString.Skip(1);        
        
            CryptoPP::BERSequenceDecoder pubKey(bitString);
            n.BERDecode(pubKey);
            e.BERDecode(pubKey);
            pubKey.MessageEnd();
        
            bitString.MessageEnd();
            mainSeq.MessageEnd();
        }
        catch(const CryptoPP::Exception& ex) {
            throw std::runtime_error("Failed to parse public key: " + std::string(ex.what()));
        }
    
        public_key_rsa.Initialize(n, e);
        is_key_loaded = true;
    }

    std::string Flux::FluxImpl::MakeRequest(const std::string& endpoint, const std::string& method, const std::string& data) {
        Flux_JUNK;
        CheckInitialization();
    
        if (debug_mode) {
            LogDebug(OBF("Making ") + method + OBF(" request to: ") + endpoint);
            if (!data.empty()) {
                LogDebug(OBF("Request data: ") + data);
            }
        }
    
        CURL* curl = curl_easy_init();
        std::string response;
    
        if (curl) {
            std::string url = API_ENDPOINT + endpoint;
        
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_USERAGENT, GetUserAgent().c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0L);
        
            if (method == OBF("POST")) {
                curl_easy_setopt(curl, CURLOPT_POST, 1L);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
            } else if (method == OBF("DELETE")) {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, OBF("DELETE"));
            } else if (method == OBF("PUT")) {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, OBF("PUT"));
                if (!data.empty()) {
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
                }
            }
        
            struct curl_slist* headers = nullptr;
            headers = curl_slist_append(headers, OBF("Content-Type: application/json"));
            headers = curl_slist_append(headers, OBF("Accept: application/json"));
        
            std::string secret_key_header = OBF("X-Secret-Key: ") + private_key;
            headers = curl_slist_append(headers, secret_key_header.c_str());
        
            if (!last_token.empty()) {
                std::string auth_header = OBF("X-Serial-Token: ") + last_token;
                headers = curl_slist_append(headers, auth_header.c_str());
            }
        
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                std::string error = curl_easy_strerror(res);
                if (debug_mode) LogDebug(OBF("Request failed: ") + error);
                throw std::runtime_error(error);
            }
        
            if (debug_mode) LogDebug(OBF("Response received: ") + response);
        
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
    
        return response;
    }

    std::string Flux::FluxImpl::MakeMultipartRequest(const std::string& endpoint, const std::string& method,
                                                   const std::map<std::string, std::string>& fields,
                                                   const std::vector<uint8_t>& file_data) const {
        Flux_JUNK;
        CheckInitialization();
    
        CURL* curl = curl_easy_init();
        std::string response;
    
        if (curl) {
            std::string url = API_ENDPOINT + endpoint;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_USERAGENT, GetUserAgent().c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        
            if (method == OBF("PUT")) {
                curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, OBF("PUT"));
            }
        
            struct curl_slist* headers = nullptr;
            if (!last_token.empty()) {
                std::string auth_header = OBF("Authorization: Bearer ") + last_token;
                headers = curl_slist_append(headers, auth_header.c_str());
            }

            std::string secret_key_header = OBF("X-Secret-Key: ") + private_key;
            headers = curl_slist_append(headers, secret_key_header.c_str());
        
            curl_mime* mime = curl_mime_init(curl);
        
            for (const auto& [key, value] : fields) {
                curl_mimepart* part = curl_mime_addpart(mime);
                curl_mime_name(part, key.c_str());
                curl_mime_data(part, value.c_str(), CURL_ZERO_TERMINATED);
            }
        
            if (!file_data.empty()) {
                curl_mimepart* part = curl_mime_addpart(mime);
                curl_mime_name(part, OBF("value"));
                curl_mime_data(part, reinterpret_cast<const char*>(file_data.data()), file_data.size());
                curl_mime_type(part, OBF("application/octet-stream"));
            }
        
            curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
            CURLcode res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                Ferror(OBF("Failed to upload file: ") + std::string(curl_easy_strerror(res)));
            }
        
            curl_mime_free(mime);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }
    
        return response;
    }

    std::vector<uint8_t> Flux::FluxImpl::DecryptFileData(const std::vector<uint8_t>& encrypted_data) const {
        Flux_JUNK;
        if (encrypted_data.size() < CryptoPP::AES::BLOCKSIZE) {
            Ferror(OBF("Invalid encrypted data size"));
        }

        std::vector<uint8_t> key(32);
        CryptoPP::StringSource(FILE_KEY, true,
            new CryptoPP::HexDecoder(
                new CryptoPP::ArraySink(key.data(), key.size())
            )
        );

        std::vector<uint8_t> iv(encrypted_data.begin(), encrypted_data.begin() + CryptoPP::AES::BLOCKSIZE);
        std::vector<uint8_t> ciphertext(encrypted_data.begin() + CryptoPP::AES::BLOCKSIZE, encrypted_data.end());

        std::vector<uint8_t> decrypted;
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key.data(), key.size(), iv.data());

        CryptoPP::ArraySource(ciphertext.data(), ciphertext.size(), true,
            new CryptoPP::StreamTransformationFilter(decryptor,
                new CryptoPP::VectorSink(decrypted),
                CryptoPP::StreamTransformationFilter::PKCS_PADDING
            )
        );

        return decrypted;
    }

    Flux::Flux(const std::string& app_id, const std::string& private_key, const std::string& name, const std::string& version, const std::string& api_endpoint, bool debug, bool encrypt_local_vars)
        : impl(new FluxImpl(app_id, name, version, private_key, api_endpoint, debug, encrypt_local_vars)) {}

    Flux::~Flux() {
        delete impl;
    }

    void Flux::Init() {
        Flux_JUNK;
        std::thread FluxAuth { refresh_fake_auth };
        FluxAuth.detach();
        Flux_START_ANTI_PAUSE_THREAD;
        //Flux_START_INTEGRITY_CHECK;
        Flux_START_ANTI_ATTACH;
        Flux_START_ANTI_DEBUG;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        if (impl->debug_mode) impl->LogDebug(OBF("FluxAuth initialized successfully"));
        impl->LoadLocalVars();
        impl->is_initialized = true;
        Flux_JUNK;
    }

    bool Flux::IsInitialized() const {
        Flux_JUNK;
        return impl->is_initialized;
    }

    bool Flux::IsAuthenticated() const {
        Flux_JUNK;
        return impl->is_authenticated;
    }

    bool Flux::Authenticate(const std::string& license, const std::string& hwid) {
        Flux_JUNK;
        impl->CheckInitialization();
    
        if (impl->application_id.empty()) {
            impl->SetLastError(OBF("Application ID not set"));
            if (impl->debug_mode) impl->LogDebug(OBF("Authentication failed: Application ID not set"));
            return false;
        }
    
        impl->current_license = license;
        std::string actual_hwid = hwid.empty() ? impl->GetMachineHWID() : hwid;
    
        if (impl->debug_mode) {
            impl->LogDebug(OBF("Attempting authentication"));
            impl->LogDebug(OBF("License: ") + license);
            impl->LogDebug(OBF("HWID: ") + actual_hwid);
        }
    
        json payload = {
            {OBF("license"), license},
            {OBF("hwid"), actual_hwid}
        };
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/authenticate"), 
                                               OBF("POST"), payload.dump());
    
        if (response.empty()) {
            impl->SetLastError(OBF("Empty response from server"));
            if (impl->debug_mode) impl->LogDebug(OBF("Authentication failed: Empty response from server"));
            return false;
        }
    
        try {
            auto j = json::parse(response);
        
            if (j.contains(OBF("message"))) {
                impl->SetLastError(j[(OBF("message"))].get<std::string>());
                if (impl->debug_mode) impl->LogDebug(OBF("Authentication failed: ") + impl->last_error);
                return false;
            }
        
            impl->is_authenticated = j.value(OBF("success"), false);
            if (j.contains(OBF("token"))) {
                impl->last_token = j[(OBF("token"))];
            }
        
            if (impl->is_authenticated) {
                if (impl->debug_mode) impl->LogDebug(OBF("Authentication successful"));
                try {
                    GetLicenseInfo();
                    impl->SetLastError("");
                } catch (const std::exception& e) {
                    impl->SetLastError(OBF("Failed to get license info"));
                    if (impl->debug_mode) impl->LogDebug(OBF("Failed to get license info: ") + std::string(e.what()));
                    return false;
                }
            } else {
                impl->SetLastError(j[(OBF("error"))]);
                if (impl->debug_mode) impl->LogDebug(OBF("Authentication failed: ") + impl->last_error);
            }
        
            return impl->is_authenticated;
        } catch (const json::exception& e) {
            impl->SetLastError(OBF("Failed to parse authentication response: ") + std::string(e.what()));
            if (impl->debug_mode) impl->LogDebug(OBF("Authentication failed: ") + impl->last_error);
            return false;
        }
    }

    LicenseInfo Flux::GetLicenseInfo() const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/licenses/") + impl->current_license,
                                               OBF("GET"));
    
        auto j = json::parse(response);
    
        if (j.contains(OBF("message"))) {
            Ferror(j[(OBF("message"))].get<std::string>());
        }
    
        LicenseInfo info;
        info.id = j[(OBF("id"))].get<int64_t>();
        info.hwid = j[(OBF("hwid"))].get<std::string>();
        info.revoked = j[(OBF("revoked"))].get<bool>();
        info.createdAt = j[(OBF("createdAt"))].get<int64_t>();
        info.updatedAt = j[(OBF("updatedAt"))].get<int64_t>();

        if (j.contains(OBF("duration"))) {
            info.duration = j[(OBF("duration"))].get<int64_t>();
        } else {
            info.duration = -1;     
        }

        if (j.contains(OBF("expiresAt"))) {
            info.expiresAt = j[(OBF("expiresAt"))].get<int64_t>();
        } else {
            info.expiresAt = -1;     
        }
    
        impl->user_data = info;
        return info;
    }

    const LicenseInfo* Flux::GetUserData() const {
        Flux_JUNK;
        return impl->user_data ? &*impl->user_data : nullptr;
    }

    int64_t Flux::GetExpiryTime() const {
        Flux_JUNK;
        return impl->user_data ? impl->user_data->expiresAt : 0;
    }

    bool Flux::ResetHWID() const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/licenses/") + impl->current_license + OBF("/reset"),
                                               OBF("PUT"));
    
        auto j = json::parse(response);
        bool success = j.value(OBF("success"), false);
        
        if (impl->debug_mode) {
            if (success) {
                impl->LogDebug(OBF("HWID reset successful"));
            } else {
                impl->LogDebug(OBF("HWID reset failed"));
            }
        }
        
        return success;
    }

    bool Flux::RevokeLicense() const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/licenses/") + impl->current_license + OBF("/revoke"),
                                               OBF("PUT"));
    
        auto j = json::parse(response);
        bool success = j.value(OBF("success"), false);
        
        if (impl->debug_mode) {
            if (success) {
                impl->LogDebug(OBF("License revocation successful"));
            } else {
                impl->LogDebug(OBF("License revocation failed"));
            }
        }
        
        return success;
    }

    bool Flux::DeleteLicense() const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/licenses/") + impl->current_license,
                                               OBF("DELETE"));
    
        auto j = json::parse(response);
        bool success = j.value(OBF("success"), false);
        
        if (impl->debug_mode) {
            if (success) {
                impl->LogDebug(OBF("License deletion successful"));
            } else {
                impl->LogDebug(OBF("License deletion failed"));
            }
        }
        
        return success;
    }

    bool Flux::CreateVariable(const std::string& name, const std::string& value, bool authenticated) const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        json payload = {
            {OBF("type"), OBF("String")},
            {OBF("authenticated"), authenticated},
            {OBF("value"), value}
        };
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/variables/") + name,
                                               OBF("PUT"), payload.dump());
    
        auto j = json::parse(response);
        bool success = j.value(OBF("success"), false);
        
        if (impl->debug_mode) {
            if (success) {
                impl->LogDebug(OBF("Variable created successfully: ") + name);
            } else {
                impl->LogDebug(OBF("Failed to create variable: ") + name);
            }
        }
        
        return success;
    }

    bool Flux::CreateVariable(const std::string& name, bool value, bool authenticated) const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        json payload = {
            {OBF("type"), OBF("Boolean")},
            {OBF("authenticated"), authenticated},
            {OBF("value"), value}
        };
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/variables/") + name,
                                               OBF("PUT"), payload.dump());
    
        auto j = json::parse(response);
        bool success = j.value(OBF("success"), false);
        
        if (impl->debug_mode) {
            if (success) {
                impl->LogDebug(OBF("Boolean variable created successfully: ") + name);
            } else {
                impl->LogDebug(OBF("Failed to create boolean variable: ") + name);
            }
        }
        
        return success;
    }

    bool Flux::CreateFileVariable(const std::string& name, const std::vector<uint8_t>& data, bool authenticated) const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        std::map<std::string, std::string> fields = {
            {OBF("type"), OBF("File")},
            {OBF("authenticated"), authenticated ? OBF("true") : OBF("false")}
        };
    
        std::string response = impl->MakeMultipartRequest(
            OBF("/api/v1/") + impl->application_id + OBF("/variables/") + name,
            OBF("PUT"),
            fields,
            data
        );
    
        try {
            auto j = json::parse(response);
            bool success = j.value(OBF("success"), false);
            
            if (impl->debug_mode) {
                if (success) {
                    impl->LogDebug(OBF("File variable created successfully: ") + name);
                } else {
                    impl->LogDebug(OBF("Failed to create file variable: ") + name);
                }
            }
            
            return success;
        } catch (const std::exception&) {
            if (impl->debug_mode) {
                impl->LogDebug(OBF("Failed to parse response for file variable creation: ") + name);
            }
            return false;
        }
    }

    bool Flux::DeleteVariable(const std::string& name) const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/variables/") + name,
                                               OBF("DELETE"));
    
        try {
            auto j = json::parse(response);
            bool success = j.value(OBF("success"), false);
            
            if (impl->debug_mode) {
                if (success) {
                    impl->LogDebug(OBF("Variable deleted successfully: ") + name);
                } else {
                    impl->LogDebug(OBF("Failed to delete variable: ") + name);
                }
            }
            
            return success;
        } catch (const std::exception&) {
            if (impl->debug_mode) {
                impl->LogDebug(OBF("Failed to parse response for variable deletion: ") + name);
            }
            return false;
        }
    }

    std::vector<uint8_t> Flux::DownloadFile(const std::string& name) const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/variables/") + name,
                                               OBF("GET"));
    
        if (response.empty()) {
            Ferror(OBF("Variable not found"));
        }

        try {
            auto j = json::parse(response);
        
            if (j.contains(OBF("error"))) {
                Ferror(j[(OBF("error"))].get<std::string>());
            }
        
            if (!j.contains(OBF("value")) || !j[(OBF("value"))].is_array()) {
                Ferror(OBF("Variable is not a file"));
            }
        
            std::vector<uint8_t> result = j[(OBF("value"))].get<std::vector<uint8_t>>();
            
            if (impl->debug_mode) {
                impl->LogDebug(OBF("File downloaded successfully: ") + name);
            }
            
            return result;
        } catch (const std::exception&) {
            Ferror(OBF("Failed to parse server response"));
        }
    
        return std::vector<uint8_t>();
    }

    std::string Flux::GetStringVariable(const std::string& name) const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/variables/") + name,
                                               OBF("GET"));
    
        if (response.empty()) {
            Ferror(OBF("Variable not found"));
        }

        try {
            auto j = json::parse(response);
        
            if (j.contains(OBF("error"))) {
                Ferror(j[(OBF("error"))].get<std::string>());
            }
        
            if (!j.contains(OBF("value")) || !j[(OBF("value"))].is_string()) {
                Ferror(OBF("Variable is not a string"));
            }
        
            return j[(OBF("value"))].get<std::string>();
        } catch (const std::exception&) {
            Ferror(OBF("Failed to parse server response"));
        }
    
        return std::string();
    }

    bool Flux::GetBooleanVariable(const std::string& name) const {
        Flux_JUNK;
        impl->CheckAuthentication();
    
        std::string response = impl->MakeRequest(OBF("/api/v1/") + impl->application_id + OBF("/variables/") + name,
                                               OBF("GET"));
    
        if (response.empty()) {
            Ferror(OBF("Variable not found"));
        }

        try {
            auto j = json::parse(response);
        
            if (j.contains(OBF("error"))) {
                Ferror(j[(OBF("error"))].get<std::string>());
            }
        
            if (!j.contains(OBF("value")) || !j[(OBF("value"))].is_boolean()) {
                Ferror(OBF("Variable is not a boolean"));
            }
        
            return j[(OBF("value"))].get<bool>();
        } catch (const std::exception&) {
            Ferror(OBF("Failed to parse server response"));
        }
    
        return false;
    }

    std::string Flux::GetLastError() const {
        Flux_JUNK;
        return impl->last_error;
    }

    std::string Flux::GetMachineHWID() {
        Flux_JUNK;
        return FluxImpl::GetMachineHWID();
    }

    std::string Flux::GetUserHWID() {
        Flux_JUNK;
        return FluxImpl::GetUserHWID();
    }

    void Flux::SetWebhookUrl(const std::string& url) {
        impl->webhook_url = url;
        if (impl->debug_mode) {
            impl->LogDebug(OBF("Webhook URL set to: ") + url);
        }
    }

    bool Flux::SendWebhook(const std::string& content, const std::map<std::string, std::string>& fields) const {
        return impl->SendWebhook(content, fields);
    }

    bool Flux::SetLocalVar(const std::string& name, const std::string& value) {
        impl->local_vars[name] = {LocalVarType::STRING, value};
        impl->SaveLocalVars();
        return true;
    }

    bool Flux::SetLocalVar(const std::string& name, int64_t value) {
        impl->local_vars[name] = {LocalVarType::INTEGER, value};
        impl->SaveLocalVars();
        return true;
    }

    bool Flux::SetLocalVar(const std::string& name, bool value) {
        impl->local_vars[name] = {LocalVarType::BOOLEAN, value};
        impl->SaveLocalVars();
        return true;
    }

    bool Flux::SetLocalVar(const std::string& name, double value) {
        impl->local_vars[name] = {LocalVarType::DOUBLE, value};
        impl->SaveLocalVars();
        return true;
    }

    std::optional<std::string> Flux::GetLocalString(const std::string& name) const {
        auto it = impl->local_vars.find(name);
        if (it != impl->local_vars.end() && it->second.first == LocalVarType::STRING) {
            return std::get<std::string>(it->second.second);
        }
        return std::nullopt;
    }

    std::optional<int64_t> Flux::GetLocalInt(const std::string& name) const {
        auto it = impl->local_vars.find(name);
        if (it != impl->local_vars.end() && it->second.first == LocalVarType::INTEGER) {
            return std::get<int64_t>(it->second.second);
        }
        return std::nullopt;
    }

    std::optional<bool> Flux::GetLocalBool(const std::string& name) const {
        auto it = impl->local_vars.find(name);
        if (it != impl->local_vars.end() && it->second.first == LocalVarType::BOOLEAN) {
            return std::get<bool>(it->second.second);
        }
        return std::nullopt;
    }

    std::optional<double> Flux::GetLocalDouble(const std::string& name) const {
        auto it = impl->local_vars.find(name);
        if (it != impl->local_vars.end() && it->second.first == LocalVarType::DOUBLE) {
            return std::get<double>(it->second.second);
        }
        return std::nullopt;
    }

    bool Flux::DeleteLocalVar(const std::string& name) {
        auto it = impl->local_vars.find(name);
        if (it != impl->local_vars.end()) {
            impl->local_vars.erase(it);
            impl->SaveLocalVars();
            return true;
        }
        return false;
    }

    void Flux::ClearLocalVars() {
        impl->local_vars.clear();
        impl->SaveLocalVars();
    }

    bool Flux::HasLocalVar(const std::string& name) const {
        return impl->local_vars.find(name) != impl->local_vars.end();
    }

    LocalVarType Flux::GetLocalVarType(const std::string& name) const {
        auto it = impl->local_vars.find(name);
        if (it != impl->local_vars.end()) {
            return it->second.first;
        }
        throw std::runtime_error("Variable not found");
    }

    std::vector<std::string> Flux::GetLocalVarNames() const {
        std::vector<std::string> names;
        for (const auto& [name, _] : impl->local_vars) {
            names.push_back(name);
        }
        return names;
    }
}
