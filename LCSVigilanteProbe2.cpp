#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {
constexpr DWORD kExpectedTimestamp = 0x504D6947;
constexpr DWORD kExpectedImageSize = 0x00614000;
constexpr DWORD kExpectedEntryPoint = 0x00267BF0;
constexpr DWORD kExpectedChecksum = 0x002FEA85;
constexpr DWORD kCopPursuitMethodRva = 0x000D2260;
constexpr DWORD kCopPursuitMessageRva = 0x0029115C;

const BYTE kCopPursuitPrologue[] = {
    0x53, 0x56, 0x89, 0xCB, 0x57, 0x55, 0x83, 0xEC,
    0x20, 0x8B, 0x43, 0x10, 0x05, 0x20, 0x4E, 0x00
};
constexpr char kCopPursuitMessage[] = "CopPursuit total messed up: re-setting";

void Log(const char* message) {
    char line[1024]{};
    std::snprintf(line, sizeof(line), "[LCSVigilanteProbe2] %s\r\n", message);
    OutputDebugStringA(line);

    HANDLE file = CreateFileA("LCSVigilanteProbe2.log", FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(file, line, static_cast<DWORD>(std::strlen(line)), &written, nullptr);
        CloseHandle(file);
    }
}

void LogValue(const char* label, DWORD value) {
    char line[256]{};
    std::snprintf(line, sizeof(line), "%s=0x%08lX", label,
                  static_cast<unsigned long>(value));
    Log(line);
}

DWORD WINAPI ProbeThread(void*) {
    HMODULE exe = GetModuleHandleA(nullptr);
    if (!exe) {
        Log("FAIL: GetModuleHandle(NULL) returned null.");
        return 0;
    }

    const auto base = reinterpret_cast<std::uintptr_t>(exe);
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        Log("FAIL: main module is not a valid PE image.");
        return 0;
    }

    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        Log("FAIL: main module is not the expected 32-bit PE image.");
        return 0;
    }

    Log("Loaded into the game process.");
    LogValue("EXE_BASE", static_cast<DWORD>(base));
    LogValue("PE_TIMESTAMP", nt->FileHeader.TimeDateStamp);
    LogValue("IMAGE_SIZE", nt->OptionalHeader.SizeOfImage);
    LogValue("ENTRY_POINT_RVA", nt->OptionalHeader.AddressOfEntryPoint);
    LogValue("PE_CHECKSUM", nt->OptionalHeader.CheckSum);

    const bool imageMatches =
        nt->FileHeader.TimeDateStamp == kExpectedTimestamp &&
        nt->OptionalHeader.SizeOfImage == kExpectedImageSize &&
        nt->OptionalHeader.AddressOfEntryPoint == kExpectedEntryPoint &&
        nt->OptionalHeader.CheckSum == kExpectedChecksum;

    if (!imageMatches) {
        Log("FAIL: executable fingerprint differs from the analyzed Re:LCS build; no game memory was modified.");
        return 0;
    }
    Log("PASS: executable fingerprint matches the analyzed Re:LCS executable.");

    const auto code = reinterpret_cast<const BYTE*>(base + kCopPursuitMethodRva);
    if (std::memcmp(code, kCopPursuitPrologue, sizeof(kCopPursuitPrologue)) != 0) {
        Log("FAIL: CopPursuit candidate bytes do not match; no game memory was modified.");
        return 0;
    }

    const auto message = reinterpret_cast<const char*>(base + kCopPursuitMessageRva);
    if (std::strcmp(message, kCopPursuitMessage) != 0) {
        Log("FAIL: CopPursuit diagnostic string does not match; no game memory was modified.");
        return 0;
    }

    LogValue("COP_PURSUIT_CANDIDATE", static_cast<DWORD>(base + kCopPursuitMethodRva));
    Log("PASS: CopPursuit candidate signature and diagnostic string match.");
    Log("DIAGNOSTIC ONLY: no hooks installed, no game functions called, and no memory patched.");
    return 0;
}
} // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        HANDLE thread = CreateThread(nullptr, 0, ProbeThread, nullptr, 0, nullptr);
        if (thread) CloseHandle(thread);
        else OutputDebugStringA("[LCSVigilanteProbe2] Failed to create diagnostic thread.\r\n");
    }
    return TRUE;
}
