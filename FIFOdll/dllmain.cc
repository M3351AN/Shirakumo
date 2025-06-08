#include <Windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#define kInitFifo 0xF1F0
#define kFifoReadVm 0xF1F01
#define kFifoWriteVm 0xF1F02
#define kFifoDllBase 0xF1F04

#pragma pack(push, 1)
struct FixedStr64 {
  uint64_t blocks[4];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Requests {
  int request_key;

  uint64_t src_pid;
  uint64_t src_addr;
  uint64_t dst_pid;
  uint64_t dst_addr;
  size_t size;

  DWORD dwFlags;
  DWORD dx;
  DWORD dy;
  DWORD dwData;
  ULONG_PTR dwExtraInfo;

  uint64_t dll_base;

  FixedStr64 dll_name;
  size_t dll_name_length;
};
#pragma pack(pop)

HANDLE hSrcProcess = 0;
HANDLE hDstProcess = 0;

std::string decodeFixedStr64(const FixedStr64& fs) {
  std::string result;
  for (int i = 0; i < 4; ++i) {
    uint64_t block = fs.blocks[i];
    for (int j = 0; j < 8; ++j) {
      char c = static_cast<char>((block >> (56 - j * 8)) & 0xFF);
      if (c == '\0') break;
      result += c;
    }
  }
  return result;
}

uint64_t getDllBase(DWORD pid, const std::string& dllName) {
  HANDLE hSnapshot =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

  MODULEENTRY32 me;
  me.dwSize = sizeof(me);
  uint64_t base = 0;

  if (Module32First(hSnapshot, &me)) {
    do {
      std::wstring modName(me.szModule);
      std::string narrowModName(modName.begin(), modName.end());

      if (_stricmp(narrowModName.c_str(), dllName.c_str()) == 0) {
        base = reinterpret_cast<uint64_t>(me.modBaseAddr);
        break;
      }
    } while (Module32Next(hSnapshot, &me));
  }

  CloseHandle(hSnapshot);
  return base;
}

static inline void handleReadVm(Requests* req) noexcept {
  if (!hSrcProcess || !hDstProcess) {
    return;
  }
  thread_local static char buffer[0xCAFE];

  SIZE_T bytesRead = 0;
  if (ReadProcessMemory(hSrcProcess, reinterpret_cast<LPCVOID>(req->src_addr),
                        buffer, req->size, &bytesRead)) {
    WriteProcessMemory(hDstProcess, reinterpret_cast<LPVOID>(req->dst_addr),
                       buffer, bytesRead, nullptr);
  }
}

static inline void handleWriteVm(Requests* req) noexcept {
  if (!hSrcProcess || !hDstProcess) {
    return;
  }
  thread_local static char buffer[0xCAFE];

  SIZE_T bytesRead = 0;
  if (ReadProcessMemory(hSrcProcess, reinterpret_cast<LPCVOID>(req->dst_addr),
                        buffer, req->size, &bytesRead)) {
    WriteProcessMemory(hDstProcess, reinterpret_cast<LPVOID>(req->src_addr),
                       buffer, bytesRead, nullptr);
  }
}

DWORD WINAPI FIFOThread(LPVOID) {
  const char* PIPE_NAME = "\\\\.\\pipe\\Shirakumo";

  while (true) {
    printf("[+] Create Named Pipe: %s\n", PIPE_NAME);
    HANDLE hPipe = CreateNamedPipeA(
        PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, sizeof(Requests), sizeof(Requests), 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
      printf("[-] Create Pipe Failed (Err: %lu)\n", GetLastError());
      return 1;
    }

    printf("[+] Waiting Client...\n");
    if (!ConnectNamedPipe(hPipe, NULL)) {
      printf("[-] Connect Failed (Err: %lu)\n", GetLastError());
      CloseHandle(hPipe);
      continue;
    }

    printf("[+] Client Connected\n");

    Requests req;
    DWORD bytesRead;
    while (true) {
      if (!ReadFile(hPipe, &req, sizeof(req), &bytesRead, NULL)) {
        printf("[-] Read Failed (Err: %lu)\n", GetLastError());
        break;
      }

      if (bytesRead != sizeof(req)) {
        printf("[-] Request Packet Size Err: %lu/%zu\n", bytesRead,
               sizeof(req));
        break;
      }

      switch (req.request_key) {
        case kInitFifo:

          printf("[+] Init: PID=%llu fromPID=%llu\n", req.src_pid, req.dst_pid);
          CloseHandle(hSrcProcess);
          CloseHandle(hDstProcess);
          hSrcProcess = OpenProcess(PROCESS_VM_READ, FALSE,
                                    static_cast<DWORD>(req.src_pid));
          hDstProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                                    FALSE, static_cast<DWORD>(req.dst_pid));
          break;

        case kFifoReadVm:
#ifndef NDEBUG
          printf("[+] Read: SRC_PID=%llu, ADDR=0x%p, SIZE=%zu\n", req.src_pid,
                 (void*)req.src_addr, req.size);
#endif  // !NDEBUG

          handleReadVm(&req);
          break;

        case kFifoWriteVm:
#ifndef NDEBUG
          printf("[+] Write: DST_PID=%llu, ADDR=0x%p, SIZE=%zu\n", req.src_pid,
                 (void*)req.src_addr, req.size);
#endif  // !NDEBUG
          handleWriteVm(&req);
          break;

        case kFifoDllBase: {
          std::string dllName = decodeFixedStr64(req.dll_name);
          printf("[+] Get DLL Base: PID=%llu, DLL='%s'\n", req.src_pid,
                 dllName.c_str());
          req.dll_base = getDllBase(static_cast<DWORD>(req.src_pid), dllName);
          printf("   Base Addr: 0x%p\n", (void*)req.dll_base);
          break;
        }

        default:
          printf("[-] Unk Request: 0x%X\n", req.request_key);
      }

      DWORD bytesWritten;
      if (!WriteFile(hPipe, &req, sizeof(req), &bytesWritten, NULL)) {
        printf("[-] Write Failed (Err: %lu)\n", GetLastError());
        break;
      }
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    CloseHandle(hSrcProcess);
    CloseHandle(hDstProcess);
    printf("[+] Connection Closed\n\n");
  }

  return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      DisableThreadLibraryCalls(hModule);
      CreateThread(nullptr, 0, FIFOThread, nullptr, 0, nullptr);
      break;
  }
  return TRUE;
}
