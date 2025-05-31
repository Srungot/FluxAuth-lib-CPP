#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <string>
#include <random>
#include <ctime>
#include <windows.h>
#include <lmcons.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>
#include <thread>
#include <Psapi.h>
#include <array>
#include <memory>
#include <stdexcept>
#include <tlhelp32.h>
#include <mutex>
#include <numeric>    
#include <algorithm> 
#include <accctrl.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <winternl.h>

volatile int chaos_seedx = 10003;
DWORD64 FFunction_Addressz;

#define FPINK "\033[38;5;213m"
#define FCYAN "\033[36m"
#define FRESET "\033[0m"


#define fluxAbTdhF(x) do { \
    volatile int _crazy_var1 = 0xDEADC0DE; \
    volatile float _crazy_var2 = 3.14159265358979323846f; \
    volatile double _crazy_var3 = 2.718281828459045; \
    volatile long long _crazy_var4 = 0xCAFEBABEDEADBEEF; \
    volatile short _crazy_arr[128]; \
    volatile char _crazy_char_arr[256]; \
    volatile int _jmp_table[32]; \
    volatile int _jmp_history[64] = {0}; \
    volatile int _jmp_index = 0; \
    volatile int _layer = 0; \
    \
    for (int i = 0; i < 32; i++) { \
        _jmp_table[i] = (chaos_seedx ^ i) % 32; \
    } \
    chaos_seedx = (chaos_seedx * 0x8088405 + 1) & 0xFFFFFFFF; \
    \
    for (volatile int _a_ = 0; _a_ < 100; ++_a_) { \
        _crazy_var1 ^= (_a_ * 0x1337); \
        if (_a_ % 11 == 0 && _layer < 3) { \
            _jmp_history[_jmp_index++ % 64] = _a_; \
            _layer++; \
        } \
        \
        for (volatile int _b_ = 0; _b_ < 30; ++_b_) { \
            _crazy_var2 *= (1.0f + (_b_ * 0.01f)); \
            if (_b_ % 15 == 1 && _layer > 0) { \
                _jmp_history[_jmp_index++ % 64] = _b_; \
                _layer--; \
            } \
            \
            if (((_crazy_var1 ^ _a_) & (_b_ + 1)) % 7 == 0) { \
                _crazy_var3 += _crazy_var2 / (1.0 + _a_); \
                if (((_crazy_var1 + _a_ * _b_) % (_b_ + 5)) == 0) { \
                    _crazy_var4 ^= (0xF00D << (_a_ % 16)); \
                    switch ((_crazy_var1 ^ (_a_ * _b_)) % 20) { \
                        case 0: _crazy_arr[_a_ % 128] = _b_; break; \
                        case 1: _crazy_var1 = ~_crazy_var1; break; \
                        case 2: _crazy_var2 = -_crazy_var2; break; \
                        case 3: _crazy_var3 *= 0.5; break; \
                        case 4: _crazy_var4 >>= 1; break; \
                        case 5: _crazy_char_arr[(_a_ + _b_) % 256] = _a_ ^ _b_; break; \
                        case 6: _crazy_var1 = _crazy_var1 | (1 << (_a_ % 32)); break; \
                        case 7: _crazy_var2 += _crazy_var3 / 1000.0f; break; \
                        case 8: _crazy_var3 = (_crazy_var3 > 1000) ? 0 : _crazy_var3 * 2; break; \
                        case 9: _crazy_var4 = (_crazy_var4 * 7) % 0xFFFFFFFFFFFF; break; \
                        case 10: _crazy_arr[(_a_ * _b_) % 128] = _a_ + _b_; break; \
                        case 11: _crazy_var1 = _crazy_var1 & ~(1 << (_b_ % 32)); break; \
                        case 12: _crazy_var2 *= (_a_ % 2) ? 1.5f : 0.5f; break; \
                        case 13: _crazy_var3 += sin((double)_a_ / (double)(_b_ + 1)); break; \
                        case 14: _crazy_var4 ^= (0x1234ABCD << (_b_ % 8)); break; \
                        case 15: _crazy_arr[(_a_ + _b_ * 3) % 128] = _a_ * _b_; break; \
                        case 16: _jmp_history[_jmp_index++ % 64] = 16; break; \
                        case 17: _crazy_var1 = _crazy_var1 ^ (chaos_seedx * _a_ * _b_); break; \
                        case 18: if (_layer < 3) { _layer++; } break; \
                        case 19: _crazy_arr[(_a_ * _b_) % 128] ^= 0xFFFF; break; \
                    } \
                } \
            } \
            \
            if ((_a_ ^ _b_) % 3 == 0) { _crazy_var1 += _a_ * _b_; } \
            if ((_a_ + _b_) % 5 == 0) { _crazy_var3 *= 1.001; } \
            if ((_a_ * _b_) % 7 == 0) { _crazy_var4 ^= (1ULL << (_a_ % 63)); } \
            \
            for (volatile int _c_ = 0; _c_ < 5 && _c_ < _b_; ++_c_) { \
                    _crazy_var1 = (_crazy_var1 * 0x17489 + 0x24A63) & 0xFFFFFFFF; \
                    _crazy_arr[(_a_ + _b_ + _c_) % 128] = _c_ ^ _a_ ^ _b_; \
                if (_c_ % 3 == 0) { \
                    _crazy_var2 *= exp(sin((float)_c_ / 10.0f)); \
                } else if (_c_ % 3 == 1) { \
                    _crazy_var3 = tan(_crazy_var3 / 100.0) * 10.0; \
                } else { \
                    _crazy_var4 ^= (chaos_seedx ^ 0xBAADF00D) * _c_; \
                } \
            } \
        } \
    } \
    \
    if (_crazy_var1 == 0x12345678 && _crazy_var4 == 0x87654321) { \
        for (int i = 0; i < 128; i++) { _crazy_arr[i] = 0; } \
    } \
    x; \
} while (0)

#define fluxJkDpomZd(x) do { \
    volatile int _crazy_var1 = 0xDEADC0DE; \
    volatile float _crazy_var2 = 3.14159265358979323846f; \
    volatile double _crazy_var3 = 2.718281828459045; \
    volatile long long _crazy_var4 = 0xCAFEBABEDEADBEEF; \
    volatile short _crazy_arr[128]; \
    volatile char _crazy_char_arr[256]; \
    volatile int _jmp_table[32]; \
    volatile int _jmp_history[64] = {0}; \
    volatile int _jmp_index = 0; \
    volatile int _layer = 0; \
    \
    for (int i = 0; i < 32; i++) { \
        _jmp_table[i] = (chaos_seedx ^ i) % 32; \
    } \
    chaos_seedx = (chaos_seedx * 0x8088405 + 1) & 0xFFFFFFFF; \
    \
    for (volatile int _a_ = 0; _a_ < 100; ++_a_) { \
        _crazy_var1 ^= (_a_ * 0x1337); \
        if (_a_ % 11 == 0 && _layer < 3) { \
            _jmp_history[_jmp_index++ % 64] = _a_; \
            _layer++; \
        } \
        \
        for (volatile int _b_ = 0; _b_ < 30; ++_b_) { \
            _crazy_var2 *= (1.0f + (_b_ * 0.01f)); \
            if (_b_ % 15 == 1 && _layer > 0) { \
                _jmp_history[_jmp_index++ % 64] = _b_; \
                _layer--; \
            } \
            \
            if (((_crazy_var1 ^ _a_) & (_b_ + 1)) % 7 == 0) { \
                _crazy_var3 += _crazy_var2 / (1.0 + _a_); \
                if (((_crazy_var1 + _a_ * _b_) % (_b_ + 5)) == 0) { \
                    _crazy_var4 ^= (0xF00D << (_a_ % 16)); \
                    switch ((_crazy_var1 ^ (_a_ * _b_)) % 20) { \
                        case 0: _crazy_arr[_a_ % 128] = _b_; break; \
                        case 1: _crazy_var1 = ~_crazy_var1; break; \
                        case 2: _crazy_var2 = -_crazy_var2; break; \
                        case 3: _crazy_var3 *= 0.5; break; \
                        case 4: _crazy_var4 >>= 1; break; \
                        case 5: _crazy_char_arr[(_a_ + _b_) % 256] = _a_ ^ _b_; break; \
                        case 6: _crazy_var1 = _crazy_var1 | (1 << (_a_ % 32)); break; \
                        case 7: _crazy_var2 += _crazy_var3 / 1000.0f; break; \
                        case 8: _crazy_var3 = (_crazy_var3 > 1000) ? 0 : _crazy_var3 * 2; break; \
                        case 9: _crazy_var4 = (_crazy_var4 * 7) % 0xFFFFFFFFFFFF; break; \
                        case 10: _crazy_arr[(_a_ * _b_) % 128] = _a_ + _b_; break; \
                        case 11: _crazy_var1 = _crazy_var1 & ~(1 << (_b_ % 32)); break; \
                        case 12: _crazy_var2 *= (_a_ % 2) ? 1.5f : 0.5f; break; \
                        case 13: _crazy_var3 += sin((double)_a_ / (double)(_b_ + 1)); break; \
                        case 14: _crazy_var4 ^= (0x1234ABCD << (_b_ % 8)); break; \
                        case 15: _crazy_arr[(_a_ + _b_ * 3) % 128] = _a_ * _b_; break; \
                        case 16: _jmp_history[_jmp_index++ % 64] = 16; break; \
                        case 17: _crazy_var1 = _crazy_var1 ^ (chaos_seedx * _a_ * _b_); break; \
                        case 18: if (_layer < 3) { _layer++; } break; \
                        case 19: _crazy_arr[(_a_ * _b_) % 128] ^= 0xFFFF; break; \
                    } \
                } \
            } \
            \
            if ((_a_ ^ _b_) % 3 == 0) { _crazy_var1 += _a_ * _b_; } \
            if ((_a_ + _b_) % 5 == 0) { _crazy_var3 *= 1.001; } \
            if ((_a_ * _b_) % 7 == 0) { _crazy_var4 ^= (1ULL << (_a_ % 63)); } \
            \
            for (volatile int _c_ = 0; _c_ < 5 && _c_ < _b_; ++_c_) { \
                _crazy_var1 = (_crazy_var1 * 0x17489 + 0x24A63) & 0xFFFFFFFF; \
                _crazy_arr[(_a_ + _b_ + _c_) % 128] = _c_ ^ _a_ ^ _b_; \
                if (_c_ % 3 == 0) { \
                    _crazy_var2 *= exp(sin((float)_c_ / 10.0f)); \
                } else if (_c_ % 3 == 1) { \
                    _crazy_var3 = tan(_crazy_var3 / 100.0) * 10.0; \
                } else { \
                    _crazy_var4 ^= (chaos_seedx ^ 0xBAADF00D) * _c_; \
                } \
            } \
        } \
    } \
    \
    if (_crazy_var1 == 0x12345678 && _crazy_var4 == 0x87654321) { \
        for (int i = 0; i < 128; i++) { _crazy_arr[i] = 0; } \
    } \
    x; \
} while (0)

#define Flux_JUNK do { \
    if (rand() % 2) { \
        fluxAbTdhF(0); \
        fluxAbTdhF(0); \
    } else { \
        fluxJkDpomZd(0); \
    } \
} while(0)

#define Flux_BUG_IDA do { \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
    fluxAbTdhF(0); \
    fluxJkDpomZd(0); \
} while(0)


struct FluxThreadInfo {
    DWORD threadId;
    HANDLE handle;
    std::chrono::steady_clock::time_point lastCheck;
    bool isActive;
};

std::vector<FluxThreadInfo> Fprotected_threads;
std::mutex Fthreads_mutex;

void fluxupdate_Fprotected_threads() {
    std::lock_guard<std::mutex> lock(Fthreads_mutex);

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    DWORD currentPID = GetCurrentProcessId();

    Fprotected_threads.erase(
        std::remove_if(Fprotected_threads.begin(), Fprotected_threads.end(),
            [](const FluxThreadInfo& info) {
                DWORD exitCode;
                return !GetExitCodeThread(info.handle, &exitCode) || exitCode != STILL_ACTIVE;
            }
        ),
        Fprotected_threads.end()
    );

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == currentPID) {
                auto it = std::find_if(Fprotected_threads.begin(), Fprotected_threads.end(),
                    [&te32](const FluxThreadInfo& info) { return info.threadId == te32.th32ThreadID; });

                if (it == Fprotected_threads.end()) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                    if (hThread) {
                        Fprotected_threads.push_back({
                            te32.th32ThreadID,
                            hThread,
                            std::chrono::steady_clock::now(),
                            true
                            });
                    }
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
}


__forceinline void fluxanti_pause_thread() {
    while (true) {
        fluxAbTdhF(0);
        fluxupdate_Fprotected_threads();
        {
            std::lock_guard<std::mutex> lock(Fthreads_mutex);
            for (auto& thread : Fprotected_threads) {
                DWORD suspendCount = 0;
                CONTEXT context = { 0 };
                context.ContextFlags = CONTEXT_ALL;

                HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                if (ntdll) {
                    typedef NTSTATUS(NTAPI* NtQueryInformationThreadType)(
                        HANDLE ThreadHandle,
                        THREADINFOCLASS ThreadInformationClass,
                        PVOID ThreadInformation,
                        ULONG ThreadInformationLength,
                        PULONG ReturnLength
                        );

                    auto NtQueryInformationThread = (NtQueryInformationThreadType)GetProcAddress(
                        ntdll, "NtQueryInformationThread");

                    if (NtQueryInformationThread) {
                        ULONG suspendCount = 0;
                        if (NT_SUCCESS(NtQueryInformationThread(
                            thread.handle,
                            (THREADINFOCLASS)35,
                            &suspendCount,
                            sizeof(suspendCount),
                            NULL))) {
                            if (suspendCount > 0) {
                                while (ResumeThread(thread.handle) > 0) {}
                            }
                        }
                    }
                }

                DWORD exitCode;
                if (GetExitCodeThread(thread.handle, &exitCode)) {
                    if (exitCode != STILL_ACTIVE) {
                    }
                }
            }
        }
        fluxAbTdhF(0);
        Sleep(50);
    }
}

#define Flux_START_ANTI_PAUSE_THREAD std::thread([]() { fluxanti_pause_thread(); }).detach()

#pragma once
#include <Windows.h>
#include <string>
#include <accctrl.h>
#include <aclapi.h>
#include <bcrypt.h>

inline bool LockMemAccessz()
{
    bool bSuccess = false;
    HANDLE hToken = nullptr;
    PTOKEN_USER pTokenUser = nullptr;
    DWORD cbBufferSize = 0;

    PACL pACL = nullptr;
    DWORD cbACL = 0;

    if (!OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_QUERY,
        &hToken
    )) {
        goto Cleanup;
    }

    GetTokenInformation(
        hToken,
        TokenUser,
        nullptr,
        0,
        &cbBufferSize
    );

    pTokenUser = static_cast<PTOKEN_USER>(malloc(cbBufferSize));
    if (pTokenUser == nullptr) {
        goto Cleanup;
    }

    if (!GetTokenInformation(
        hToken,
        TokenUser,
        pTokenUser,
        cbBufferSize,
        &cbBufferSize
    )) {
        goto Cleanup;
    }

    if (!IsValidSid(pTokenUser->User.Sid)) {
        goto Cleanup;
    }

    cbACL = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pTokenUser->User.Sid);

    pACL = static_cast<PACL>(malloc(cbACL));
    if (pACL == nullptr) {
        goto Cleanup;
    }

    if (!InitializeAcl(pACL, cbACL, ACL_REVISION)) {
        goto Cleanup;
    }

    if (!AddAccessAllowedAce(
        pACL,
        ACL_REVISION,
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
        pTokenUser->User.Sid
    )) {
        goto Cleanup;
    }

    bSuccess = ERROR_SUCCESS == SetSecurityInfo(
        GetCurrentProcess(),
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr, nullptr,
        pACL,
        nullptr
    );

Cleanup:

    if (pACL != nullptr) {
        free(pACL);

    }
    if (pTokenUser != nullptr) {
        free(pTokenUser);

    }
    if (hToken != nullptr) {
        CloseHandle(hToken);

    }
    return bSuccess;
}

namespace obffu
{
    template<class _Ty>
    using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

    template <int _size, char _key1, char _key2, typename T>
    class skCrypter
    {
    public:
        __forceinline constexpr skCrypter(T* data)
        {
            crypt(data);
        }

        __forceinline T* get()
        {
            return _storage;
        }

        __forceinline int size()
        {
            return _size;
        }

        __forceinline  char key()
        {
            return _key1;
        }

        __forceinline  T* encrypt()
        {
            if (!isEncrypted())
                crypt(_storage);

            return _storage;
        }

        __forceinline  T* decrypt()
        {
            if (isEncrypted())
                crypt(_storage);

            return _storage;
        }

        __forceinline bool isEncrypted()
        {
            return _storage[_size - 1] != 0;
        }

        __forceinline void clear()
        {
            for (int i = 0; i < _size; i++)
            {
                _storage[i] = 0;
            }
        }

        __forceinline operator T* ()
        {
            decrypt();

            return _storage;
        }

    private:
        __forceinline constexpr void crypt(T* data)
        {
            for (int i = 0; i < _size; i++)
            {
                _storage[i] = data[i] ^ (_key1 + i % (1 + _key2));
            }
        }

        T _storage[_size]{};
    };
}

#define OBF(str) KEyy(str, __TIME__[4], __TIME__[7]).decrypt()
#define KEyy(str, key1, key2) []() { \
            Flux_JUNK; \
            constexpr static auto crypted = obffu::skCrypter<sizeof(str) / sizeof(str[0]), key1, key2, \
                obffu::clean_type<decltype(str[0])>>((obffu::clean_type<decltype(str[0])>*)str); \
            Flux_JUNK; \
            return crypted; \
        }()

void Ferror(const std::string& message) {
    std::string cmd = OBF("start cmd /C \"color D && title ") + std::string(".") + OBF("Security Alert") +
        OBF(" && echo ") + std::string(FPINK) + message +
        std::string(FRESET) + OBF(" && timeout /t 5\"");
    system(cmd.c_str());
}

void Ferror(const char* message) {
    Ferror(std::string(message));
}

template<size_t _size, char _key1, char _key2, typename T>
void Ferror(std::string& message) {
    Ferror(std::string(message));
}

bool FluxcheckAcceleratorIntegrityz() {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hRsrc = FindResource(hModule, MAKEINTRESOURCE(1), RT_ACCELERATOR);

    if (hRsrc) {
        Ferror(OBF("Critical security violation: Unauthorized accelerator table detected"));
        return false;
    }
    return true;
}

bool FbDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    MODULEINFO mi{ };
    GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(NULL), &mi, sizeof(mi));

    DWORD64 dwBaseAddress = DWORD64(mi.lpBaseOfDll);
    const auto dwModuleSize = mi.SizeOfImage;

    for (auto i = 0ul; i < dwModuleSize; i++)
    {
        if (FbDataCompare(PBYTE(dwBaseAddress + i), bMask, szMask))
            return DWORD64(dwBaseAddress + i);
    }
    return NULL;
}

DWORD64 FFindPatternz(BYTE* bMask, const char* szMask)
{
    MODULEINFO mi{ };
    GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(NULL), &mi, sizeof(mi));

    DWORD64 dwBaseAddress = DWORD64(mi.lpBaseOfDll);
    const auto dwModuleSize = mi.SizeOfImage;

    for (auto i = 0ul; i < dwModuleSize; i++)
    {
        if (FbDataCompare(PBYTE(dwBaseAddress + i), bMask, szMask))
            return DWORD64(dwBaseAddress + i);
    }
    return NULL;
}

auto Fcheck_section_integrityz(const char* section_name, bool fix = false) -> bool
{
    const auto hmodule = GetModuleHandle(0);
    if (!hmodule) {
        Ferror(OBF("Memory integrity check failed: Invalid module handle"));
        return true;
    }

    const auto base_0 = reinterpret_cast<std::uintptr_t>(hmodule);
    if (!base_0) {
        Ferror(OBF("Memory integrity check failed: Invalid base address"));
        return true;
    }

    const auto dos_0 = reinterpret_cast<IMAGE_DOS_HEADER*>(base_0);
    if (dos_0->e_magic != IMAGE_DOS_SIGNATURE) {
        Ferror(OBF("Memory integrity check failed: Invalid DOS signature"));
        return true;
    }

    const auto nt_0 = reinterpret_cast<IMAGE_NT_HEADERS*>(base_0 + dos_0->e_lfanew);
    if (nt_0->Signature != IMAGE_NT_SIGNATURE) {
        Ferror(OBF("Memory integrity check failed: Invalid NT signature"));
        return true;
    }

    auto section_0 = IMAGE_FIRST_SECTION(nt_0);

    wchar_t filename[MAX_PATH];
    DWORD size = MAX_PATH;
    QueryFullProcessImageNameW(GetCurrentProcess(), 0, filename, &size);

    const auto file_handle = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (!file_handle || file_handle == INVALID_HANDLE_VALUE) {
        Ferror(OBF("Memory integrity check failed: Unable to open process file"));
        return true;
    }

    const auto file_mapping = CreateFileMapping(file_handle, 0, PAGE_READONLY, 0, 0, 0);
    if (!file_mapping)
    {
        CloseHandle(file_handle);
        Ferror(OBF("Memory integrity check failed: Unable to create file mapping("));
        return true;
    }

    const auto base_1 = reinterpret_cast<std::uintptr_t>(MapViewOfFile(file_mapping, FILE_MAP_READ, 0, 0, 0));
    if (!base_1)
    {
        CloseHandle(file_mapping);
        CloseHandle(file_handle);
        Ferror(OBF("Memory integrity check failed: Unable to map view of file"));
        return true;
    }

    const auto dos_1 = reinterpret_cast<IMAGE_DOS_HEADER*>(base_1);
    if (dos_1->e_magic != IMAGE_DOS_SIGNATURE)
    {
        UnmapViewOfFile(reinterpret_cast<void*>(base_1));
        CloseHandle(file_mapping);
        CloseHandle(file_handle);
        Ferror(OBF("Memory integrity check failed: Invalid DOS signature in mapped file"));
        return true;
    }

    const auto nt_1 = reinterpret_cast<IMAGE_NT_HEADERS*>(base_1 + dos_1->e_lfanew);
    if (nt_1->Signature != IMAGE_NT_SIGNATURE ||
        nt_1->FileHeader.TimeDateStamp != nt_0->FileHeader.TimeDateStamp ||
        nt_1->FileHeader.NumberOfSections != nt_0->FileHeader.NumberOfSections)
    {
        UnmapViewOfFile(reinterpret_cast<void*>(base_1));
        CloseHandle(file_mapping);
        CloseHandle(file_handle);
        Ferror(OBF("Memory integrity check failed: Invalid NT headers or timestamps"));
        return true;
    }

    auto section_1 = IMAGE_FIRST_SECTION(nt_1);
    bool patched = false;

    for (auto i = 0; i < nt_1->FileHeader.NumberOfSections; ++i, ++section_0, ++section_1)
    {
        if (strcmp(reinterpret_cast<char*>(section_0->Name), OBF(".text")) ||
            !(section_0->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            continue;
        }

        for (auto j = 0u; j < section_0->SizeOfRawData; ++j)
        {
            const auto old_value = *reinterpret_cast<BYTE*>(base_1 + section_1->PointerToRawData + j);
            const auto current_value = *reinterpret_cast<BYTE*>(base_0 + section_0->VirtualAddress + j);

            if (current_value == old_value) continue;

            if (fix)
            {
                DWORD new_protect{ PAGE_EXECUTE_READWRITE }, old_protect;
                VirtualProtect(reinterpret_cast<void*>(base_0 + section_0->VirtualAddress + j),
                    sizeof(BYTE), new_protect, &old_protect);
                *reinterpret_cast<BYTE*>(base_0 + section_0->VirtualAddress + j) = old_value;
                VirtualProtect(reinterpret_cast<void*>(base_0 + section_0->VirtualAddress + j),
                    sizeof(BYTE), old_protect, &new_protect);
            }

            patched = true;
        }
        break;
    }

    UnmapViewOfFile(reinterpret_cast<void*>(base_1));
    CloseHandle(file_mapping);
    CloseHandle(file_handle);

    if (patched && !fix) {
        Ferror(OBF("Critical security violation: Code integrity check failed"));
    }

    return patched;
}

void fluxINTEGRITY_CHECK_FUNC_NAME()
{
    Fcheck_section_integrityz(".text", true);

    while (true)
    {
        if (!FluxcheckAcceleratorIntegrityz()) {
            Ferror(OBF("Critical security violation: Resource tampering detected"));
        }

        if (Fcheck_section_integrityz(".text"), false)
        {
            Ferror(OBF("Critical security violation: Memory tampering detected"));
        }

        if (!LockMemAccessz())
        {
            Ferror(OBF("Critical security violation: Memory protection failure"));
        }

        Sleep(50);
    }
}

#define Flux_START_INTEGRITY_CHECK std::thread([]() { fluxINTEGRITY_CHECK_FUNC_NAME(); }).detach()




#define DbgBreakPoint_FUNC_SIZE 0x2
#define DbgUiRemoteBreakin_FUNC_SIZE 0x54
#define NtContinue_FUNC_SIZE 0x18

struct DWFFUNC {
    const char* name;
    FARPROC addr;
    SIZE_T size;
};

DWFFUNC ffuncList[] = {
    { OBF("DbgBreakPoint"), 0, DbgBreakPoint_FUNC_SIZE },
    { OBF("DbgUiRemoteBreakin"), 0, DbgUiRemoteBreakin_FUNC_SIZE },
    { OBF("NtContinue"), 0, NtContinue_FUNC_SIZE }
};

__forceinline void fluxanti_attach() {
    while (true) {
        Flux_JUNK;

        if (IsDebuggerPresent()) {
            Ferror(OBF("Debugger detected!"));
        }

        BOOL isRemoteDebuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);
        if (isRemoteDebuggerPresent) {
            Ferror(OBF("Remote debugger detected!"));
        }

        HANDLE hProcess = GetCurrentProcess();
        DWORD_PTR debugPort = 0;
        NTSTATUS status;

        static auto NtQueryInformationProcess = (NTSTATUS(NTAPI*)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))
            GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        if (NtQueryInformationProcess) {
            status = NtQueryInformationProcess(
                hProcess,
                ProcessDebugPort,
                &debugPort,
                sizeof(debugPort),
                NULL
            );

            if (NT_SUCCESS(status) && debugPort != 0) {
                Ferror(OBF("Debugger attachment detected!"));
            }
        }

        DWORD pid = GetCurrentProcessId();
        WCHAR modName[MAX_PATH] = { 0 };
        HANDLE hProcessEx = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

        HMODULE hMod = LoadLibraryA(OBF("ntdll.dll"));
        if (hMod) {
            for (int i = 0; i < _countof(ffuncList); ++i) {
                ffuncList[i].addr = GetProcAddress(hMod, ffuncList[i].name);
            }

            bool result = false;
            auto base_address = GetModuleHandleA(0);
            if (base_address) {
                wchar_t ntdll_lower[] = L"ntdll";
                wchar_t ntdll_upper[] = L"NTDLL";
                if (wcsstr((WCHAR*)base_address, ntdll_lower) || wcsstr((WCHAR*)base_address, ntdll_upper)) {
                    for (int i = 0; i < _countof(ffuncList); ++i) {
                        if (ffuncList[i].addr) {
                            DWORD dwOldProtect;
                            VirtualProtectEx(hProcessEx, ffuncList[i].addr, ffuncList[i].size, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                            result = WriteProcessMemory(hProcessEx, ffuncList[i].addr, ffuncList[i].addr, ffuncList[i].size, NULL);
                            VirtualProtectEx(hProcessEx, ffuncList[i].addr, ffuncList[i].size, dwOldProtect, NULL);

                            if (!result) break;
                        }
                    }
                }
            }
        }

        if (hProcessEx) {
            CloseHandle(hProcessEx);
        }

        Flux_JUNK;
        Sleep(50);
    }
}


#define Flux_START_ANTI_ATTACH std::thread([]() { fluxanti_attach(); }).detach()


struct FluxHardwareBreakpoint {
    DWORD64 address;
    DWORD type;
    bool enabled;
};

std::vector<FluxHardwareBreakpoint> Fluxhardware_breakpoints;
std::mutex fluxbreakpoints_mutex;

bool ffcheck_hardware_breakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE thread = GetCurrentThread();
    if (!GetThreadContext(thread, &ctx)) return false;

    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
        Ferror(OBF("Critical security violation: Hardware breakpoint detected!"));
        return true;
    }

    return false;
}

bool ffcheck_software_breakpoints(const BYTE* start, SIZE_T size) {
    std::vector<BYTE> buffer(size);
    memcpy(buffer.data(), start, size);

    for (SIZE_T i = 0; i < size; i++) {
        if (buffer[i] == 0xCC) {
            Ferror(OBF("Critical security violation: Software breakpoint detected!"));
            return true;
        }
    }
    return false;
}

bool ffis_blacklisted_process(const std::string& processName) {
    const std::vector<std::string> blacklist = {
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "ida.exe", "ida64.exe",
        "ghidra.exe", "dnspy.exe", "cheatengine", "processhacker.exe",
        "httpdebugger.exe", "procmon.exe", "processhacker.exe", "pestudio.exe",
        "regmon.exe", "filemon.exe", "wireshark.exe", "fiddler.exe",
        "procexp.exe", "procmon.exe", "immunitydebugger.exe", "windbg.exe",
        "debugger.exe", "dumpcap.exe", "hookexplorer.exe", "importrec.exe",
        "petools.exe", "lordpe.exe", "sysinspector.exe", "proc_analyzer.exe",
        "sysanalyzer.exe", "sniff_hit.exe", "windbg.exe", "apimonitor.exe",
        "dumpcap.exe", "networktrafficview.exe", "charles.exe", "scylla.exe"
    };

    std::string lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    return std::find_if(blacklist.begin(), blacklist.end(),
        [&lowerName](const std::string& blocked) {
            return lowerName.find(blocked) != std::string::npos;
        }) != blacklist.end();
}

bool ffcheck_parent_process() {
    DWORD pid = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                DWORD parentPID = pe32.th32ParentProcessID;
                Process32FirstW(snapshot, &pe32);

                do {
                    if (pe32.th32ProcessID == parentPID) {
                        char processName[MAX_PATH];
                        wcstombs_s(nullptr, processName, pe32.szExeFile, MAX_PATH);

                        if (ffis_blacklisted_process(processName)) {
                            Ferror(OBF("Critical security violation: Process launched from debugger/analyzer: ") +
                                std::string(processName));
                            CloseHandle(snapshot);
                            return true;
                        }
                        break;
                    }
                } while (Process32NextW(snapshot, &pe32));
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return false;
}

bool ffcheck_running_analysis_tools() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    bool found = false;

    if (Process32FirstW(snapshot, &pe32)) {
        do {
            char processName[MAX_PATH];
            wcstombs_s(nullptr, processName, pe32.szExeFile, MAX_PATH);

            if (ffis_blacklisted_process(processName)) {
                Ferror(OBF("Critical security violation: Analysis tool detected: ") + std::string(processName));
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return found;
}

__forceinline void fluxanti_debug() {
    while (true) {
        Flux_JUNK;

        if (ffcheck_hardware_breakpoints()) {
            DWORD oldProtect;
            HANDLE process = GetCurrentProcess();
            for (const auto& bp : Fluxhardware_breakpoints) {
                if (VirtualProtect((LPVOID)bp.address, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    *(BYTE*)bp.address = 0x90;
                    VirtualProtect((LPVOID)bp.address, 1, oldProtect, &oldProtect);
                }
            }
        }

        ffcheck_parent_process();
        ffcheck_running_analysis_tools();

        Flux_JUNK;
        Sleep(50);
    }
}

#define Flux_START_ANTI_DEBUG std::thread([]() { fluxanti_debug(); }).detach()