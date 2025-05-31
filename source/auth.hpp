#pragma once
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <variant>
#include <map>
#include <fstream>
#include <functional>

namespace FluxAuth {

    enum class WebhookEvent {
        LICENSE_AUTHENTICATED,
        LICENSE_EXPIRED,
        LICENSE_REVOKED,
        HWID_RESET,
        LICENSE_DELETED,
        VARIABLE_CREATED,
        VARIABLE_DELETED,
        FILE_DOWNLOADED,
        ERROR_OCCURRED
    };

    struct WebhookData {
        WebhookEvent event;
        std::string license;
        std::string hwid;
        std::string message;
        std::map<std::string, std::string> additional_data;
    };

    using WebhookCallback = std::function<void(const WebhookData&)>;

    enum class LocalVarType {
        STRING,
        INTEGER,
        BOOLEAN,
        DOUBLE
    };

    using LocalVarValue = std::variant<std::string, int64_t, bool, double>;

    struct LicenseInfo {
        int64_t id;
        std::string hwid;
        int64_t duration;
        bool revoked;
        int64_t expiresAt;
        int64_t createdAt;
        int64_t updatedAt;
    };

    class Flux {
    public:
        // name = max 7 letters
        Flux(const std::string& app_id, const std::string& private_key, const std::string& name = "FluxC++", const std::string& version = "1.0", const std::string& api_endpoint = "https://fluxauth.com", bool debug = false, bool encrypt_local_vars = true);
        ~Flux();

        void Init();
        bool Authenticate(const std::string& license, const std::string& hwid = "");
        bool IsInitialized() const;
        bool IsAuthenticated() const;
    
        LicenseInfo GetLicenseInfo() const;
        bool ResetHWID() const;
        bool DeleteLicense() const;
        bool RevokeLicense() const;
    
        bool CreateVariable(const std::string& name, const std::string& value, bool authenticated = true) const;
        bool CreateVariable(const std::string& name, bool value, bool authenticated = true) const;
        bool CreateFileVariable(const std::string& name, const std::vector<uint8_t>& data, bool authenticated = true) const;
    
        std::vector<uint8_t> DownloadFile(const std::string& name) const;
        std::string GetStringVariable(const std::string& name) const;
        bool GetBooleanVariable(const std::string& name) const;
        bool DeleteVariable(const std::string& name) const;
    
        const LicenseInfo* GetUserData() const;
        int64_t GetExpiryTime() const;
    
        std::string GetLastError() const;

        static std::string GetMachineHWID();
        static std::string GetUserHWID();

        void SetWebhookUrl(const std::string& url);
        bool SendWebhook(const std::string& content, const std::map<std::string, std::string>& fields = {}) const;

        bool SetLocalVar(const std::string& name, const std::string& value);
        bool SetLocalVar(const std::string& name, int64_t value);
        bool SetLocalVar(const std::string& name, bool value);
        bool SetLocalVar(const std::string& name, double value);
        
        std::optional<std::string> GetLocalString(const std::string& name) const;
        std::optional<int64_t> GetLocalInt(const std::string& name) const;
        std::optional<bool> GetLocalBool(const std::string& name) const;
        std::optional<double> GetLocalDouble(const std::string& name) const;
        
        bool DeleteLocalVar(const std::string& name);
        void ClearLocalVars();
        bool HasLocalVar(const std::string& name) const;
        LocalVarType GetLocalVarType(const std::string& name) const;
        std::vector<std::string> GetLocalVarNames() const;

    private:
        class FluxImpl;
        FluxImpl* impl;
    };

}