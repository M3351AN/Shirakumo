
#include <Windows.h>
#include <TlHelp32.h>
#include <fileapi.h>
#include <handleapi.h>
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
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

inline void encodeFixedStr64(const char* str, FixedStr64* fs) {
  size_t len = strlen(str);
  if (len > 32) {
    len = 32;
  }
  memset(fs->blocks, 0, sizeof(fs->blocks));
  for (size_t i = 0; i < len; i++) {
    size_t blockIndex = i / 8;
    size_t posInBlock = i % 8;
    int shift = 8 * (7 - posInBlock);
    fs->blocks[blockIndex] |=
        (static_cast<uint64_t>(static_cast<unsigned char>(str[i])) << shift);
  }
}

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

inline bool pipeRequest(HANDLE pipe_handle, Requests* req) {
  DWORD bytes_written = 0;
  if (!WriteFile(pipe_handle, req, sizeof(Requests), &bytes_written, nullptr) ||
      bytes_written != sizeof(Requests)) {
    return false;
  }

  DWORD bytes_read = 0;
  if (!ReadFile(pipe_handle, req, sizeof(Requests), &bytes_read, nullptr) ||
      bytes_read != sizeof(Requests)) {
    return false;
  }
  return true;
}

class Fifo {
 public:
  void initPipe(int process_id) {
    pipe_handle_ =
        CreateFileA("\\\\.\\pipe\\Shirakumo", GENERIC_READ | GENERIC_WRITE, 0,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (pipe_handle_ != INVALID_HANDLE_VALUE) {
      process_id_ = process_id;
    } else {
      return;
    }
    Requests out = {0};
    out.request_key = kInitFifo;
    out.src_pid = process_id_;
    out.dst_pid = static_cast<uint64_t>(GetCurrentProcessId());
    {
      std::lock_guard<std::mutex> lock(pipe_mutex_);
      if (!pipeRequest(pipe_handle_, &out)) {
        return;
      }
    }
  }

  void readSize(const uintptr_t address, const void* buffer,
                const size_t size) {
    readVm(process_id_, address, reinterpret_cast<uint64_t>(buffer), size);
  }

  template <typename T>
  void write(uintptr_t address, const T& buffer, int size) {
    writeVm(process_id_, address, reinterpret_cast<uint64_t>(&buffer), size);
  }

  ULONG64 dllAddress(const char* dll_name) {
    Requests out = {};
    out.request_key = kFifoDllBase;
    out.src_pid = process_id_;

    size_t original_len = strlen(dll_name);
    if (original_len > 32) {
      original_len = 32;
    }
    out.dll_name_length = original_len;
    FixedStr64 fs;
    encodeFixedStr64(dll_name, &fs);
    out.dll_name = fs;

    {
      std::lock_guard<std::mutex> lock(pipe_mutex_);
      if (!pipeRequest(pipe_handle_, &out)) {
        return 0;
      }
    }
    return static_cast<ULONG64>(out.dll_base);
  }

 private:
  HANDLE pipe_handle_;
  int process_id_;
  std::mutex pipe_mutex_;

  void readVm(uint32_t src_pid, uint64_t src_addr, uint64_t dst_addr,
              size_t size) {
    if (src_pid == 0 || src_addr == 0) return;

    Requests out = {kFifoReadVm, src_pid,
                    src_addr,    static_cast<uint64_t>(GetCurrentProcessId()),
                    dst_addr,    size};

    {
      std::lock_guard<std::mutex> lock(pipe_mutex_);
      if (!pipeRequest(pipe_handle_, &out)) {
      }
    }
  }

  void writeVm(uint32_t src_pid, uint64_t src_addr, uint64_t dst_addr,
               size_t size) {
    if (src_pid == 0 || dst_addr == 0) return;

    Requests out = {kFifoWriteVm, src_pid,
                    src_addr,     static_cast<uint64_t>(GetCurrentProcessId()),
                    dst_addr,     size};

    {
      std::lock_guard<std::mutex> lock(pipe_mutex_);
      if (!pipeRequest(pipe_handle_, &out)) {
      }
    }
  }
};

inline Fifo fifo;

DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }
    
    DWORD pid = 0;
    do {
        if (_wcsicmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return pid;
}

int main(void){
    fifo.initPipe(GetProcessIdByName(L"Target.exe"));
    if (fifo.dllAddress("Target.exe") == 0) {
        printf("Failed init\n");
        system("pause");
        return 1;
    }
    DWORD64 target_var;
    fifo.readSize(0xDEAD0000, &target_var, sizeof(target_var));
    printf ("readed target_var = 0x%X at 0x%llX\n", 
        target_var, 0xDEAD0000);
    printf ("done\n");
    system("pause");
    return 0;
}