#include <iostream>
#include <map>
#include <windows.h>

class Debugger {
public:
    Debugger() {}

    bool LaunchInferior(const char* program);
    void DebuggerEventLoop();
    
private:
    void ProcessDebugEvent(const DEBUG_EVENT& debug_event);
    void ProcessCreateEvent(const DEBUG_EVENT& debug_event);
    void ProcessExitEvent(const DEBUG_EVENT& debug_event);
    void ProcessExceptionEvent(const DEBUG_EVENT& debug_event);
    void ProcessOutputStringEvent(const DEBUG_EVENT& debug_event);
    void AddHardwareBreakpoint(void* addr);
    void RemoveBreakpoint(LPVOID breakpointAddress);
    void ProcessCommands();
    void PrintRegs();
    void ReadDebugRegisters();
    void ReadMemory(const char* addr_hex, int n);

    bool cont = true;
    DWORD dwContinueStatus = DBG_CONTINUE;
    CREATE_PROCESS_DEBUG_INFO pInfo = {0};
    PROCESS_INFORMATION pi = {0};
};

void Debugger::AddHardwareBreakpoint(void *addr) {
  CONTEXT lcContext;
  lcContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (!GetThreadContext(pInfo.hThread, &lcContext)) {
    printf("GetThreadContext failed: %d\n", GetLastError());
    return;
  }

  for (int i = 0; i < 4; i++) {
    if ((lcContext.Dr7 & (1 << (2 * i))) == 0) {
      // Set breakpoint
      switch (i) {
      case 0:
        lcContext.Dr0 = (DWORD_PTR)addr;
        break;
      case 1:
        lcContext.Dr1 = (DWORD_PTR)addr;
        break;
      case 2:
        lcContext.Dr2 = (DWORD_PTR)addr;
        break;
      case 3:
        lcContext.Dr3 = (DWORD_PTR)addr;
        break;
      }

      // Set breakpoint condition 00: Execute instruction breakpoint
      lcContext.Dr7 &= ~(3ull << (16 + 4 * i));

      // Set length to 00, indicating a 1-byte length
      lcContext.Dr7 &= ~(3ull << (18 + 4 * i));

      // Set local breakpoint enable flag
      lcContext.Dr7 |= (1 << (2 * i));

      if (!SetThreadContext(pInfo.hThread, &lcContext)) {
        printf("SetThreadContext failed: %d\n", GetLastError());
        return;
      }
      return;
    }
  }
  printf("No available hardware breakpoint slots\n");
}

void Debugger::RemoveBreakpoint(LPVOID breakpointAddress) {
    CONTEXT lcContext;
    lcContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(pInfo.hThread, &lcContext)) {
        std::cerr << "GetThreadContext failed: " << GetLastError() << std::endl;
        return;
    }

    if (lcContext.Dr0 == reinterpret_cast<DWORD_PTR>(breakpointAddress)) {
        lcContext.Dr0 = 0; // Clear the breakpoint address
        lcContext.Dr7 &= ~(1 << 0); // Disable the breakpoint
    }
#if 0
    if (lcContext.Dr1 == reinterpret_cast<DWORD_PTR>(breakpointAddress)) {
        lcContext.Dr1 = 0; 
        lcContext.Dr7 &= ~(1 << 2); 
    }

    if (lcContext.Dr2 == reinterpret_cast<DWORD_PTR>(breakpointAddress)) {
        lcContext.Dr2 = 0; 
        lcContext.Dr7 &= ~(1 << 4); 
    }

    if (lcContext.Dr3 == reinterpret_cast<DWORD_PTR>(breakpointAddress)) {
        lcContext.Dr3 = 0;
        lcContext.Dr7 &= ~(1 << 6); 
    }
#endif
    if (!SetThreadContext(pInfo.hThread, &lcContext)) {
        std::cerr << "SetThreadContext failed: " << GetLastError() << std::endl;
        return;
    }
}

void Debugger::ProcessExceptionEvent(const DEBUG_EVENT& debug_event) {
  DWORD code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
  switch (code) {
    case EXCEPTION_SINGLE_STEP:
      std::cout << "Single step exception (hardware breakpoint hit)" << std::endl;
      if (debug_event.u.Exception.dwFirstChance) {
        printf("Initial breakpoint exception encountered\n");
        dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
      }
      else {
        LPVOID breakpointAddress = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;                                                       printf("Breakpoint hit at address: %p\n" ,breakpointAddress);                                                     RemoveBreakpoint(breakpointAddress); 
      }
      break;
    case EXCEPTION_BREAKPOINT:
      dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
      break;
    default:
      std::cout << "Exception " << code << " (0x" << std::hex << code << ") received." << std::endl;
      break;
  }
  ProcessCommands();
}

void Debugger::ProcessCreateEvent(const DEBUG_EVENT& debug_event) {
  pInfo = debug_event.u.CreateProcessInfo;
  std::cout << "Setting a breakpoint at the start address (0x" << std::hex << pInfo.lpStartAddress << ")..." << std::endl;
  AddHardwareBreakpoint(pInfo.lpStartAddress);
}

void Debugger::ProcessExitEvent(const DEBUG_EVENT& debug_event) {
  std::cout << "Process exited with code (0x" << std::hex << debug_event.u.ExitProcess.dwExitCode << ")." << std::endl;
  cont = false;
}

void Debugger::ProcessDebugEvent(const DEBUG_EVENT& debug_event) {
  dwContinueStatus = DBG_CONTINUE;
  switch (debug_event.dwDebugEventCode) {
  case CREATE_PROCESS_DEBUG_EVENT: 
    ProcessCreateEvent(debug_event);
    break;
  case EXCEPTION_DEBUG_EVENT:
    ProcessExceptionEvent(debug_event);
    break;
  case EXIT_PROCESS_DEBUG_EVENT:
    ProcessExitEvent(debug_event);
    break;
  }
}

void Debugger::PrintRegs() {
    // Read the registers
    CONTEXT lcContext;
    lcContext.ContextFlags = CONTEXT_ALL;
    if (GetThreadContext(pi.hThread, &lcContext)) {
        // Print out all of the values of the registers
        std::printf("RAX: 0x%llx\n", lcContext.Rax);
        std::printf("RBX: 0x%llx\n", lcContext.Rbx);
        std::printf("RCX: 0x%llx\n", lcContext.Rcx);
        std::printf("RDX: 0x%llx\n", lcContext.Rdx);
        std::printf("RSP: 0x%llx\n", lcContext.Rsp);
        std::printf("RBP: 0x%llx\n", lcContext.Rbp);
        std::printf("RSI: 0x%llx\n", lcContext.Rsi);
        std::printf("RDI: 0x%llx\n", lcContext.Rdi);
        std::printf("R8: 0x%llx\n", lcContext.R8);
        std::printf("R9: 0x%llx\n", lcContext.R9);
        std::printf("R10: 0x%llx\n", lcContext.R10);
        std::printf("R11: 0x%llx\n", lcContext.R11);
        std::printf("R12: 0x%llx\n", lcContext.R12);
        std::printf("R13: 0x%llx\n", lcContext.R13);
        std::printf("R14: 0x%llx\n", lcContext.R14);
        std::printf("R15: 0x%llx\n", lcContext.R15);
        std::printf("RIP: 0x%llx\n", lcContext.Rip);
        ReadDebugRegisters();
    } else {
        std::cerr << "Failed to get thread context: " << GetLastError() << std::endl;
    }
}

void Debugger::ReadDebugRegisters() {
    // Read the debug registers
    CONTEXT lcContext;
    lcContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(pi.hThread, &lcContext)) {
        // Print out all of the values of the debug registers
        std::printf("Dr0: 0x%llx\n", lcContext.Dr0);
        std::printf("Dr1: 0x%llx\n", lcContext.Dr1);
        std::printf("Dr2: 0x%llx\n", lcContext.Dr2);
        std::printf("Dr3: 0x%llx\n", lcContext.Dr3);
        std::printf("Dr6: 0x%llx\n", lcContext.Dr6);
        std::printf("Dr7: 0x%llx\n", lcContext.Dr7);
    } else {
        std::cerr << "Failed to get debug registers context: " << GetLastError() << std::endl;
    }
}

void Debugger::ProcessCommands() {
    char cmd[200];

    while (true) {
        std::cout << "<dbg> ";
        std::cin.getline(cmd, 200);

        if (strncmp(cmd, "cont", 4) == 0) {
            break;
        } else if (strncmp(cmd, "regs", 4) == 0) {
            PrintRegs(); 
        }else if (strncmp(cmd, "q", 1) == 0) {
            std::cout << "Debugger will now exit." << std::endl;
            exit(0);
        } else if (strncmp(cmd, "help", 4) == 0) {
            std::cout << "cont: Continues execution.\n";
            std::cout << "regs: Prints all registers.\n";
            std::cout << "q: exit debug session.\n";
        }
    }
}

void Debugger::DebuggerEventLoop() {
    DEBUG_EVENT debug_event = {0};

    while (cont) {
        if (!WaitForDebugEvent(&debug_event, INFINITE)) {
            std::cerr << "WaitForDebugEvent failed: " << GetLastError() << std::endl;
            break;
        }

        ProcessDebugEvent(debug_event);
        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, dwContinueStatus);
    }

    std::cout << "Debugger will now exit." << std::endl;
}

bool Debugger::LaunchInferior(const char* program) {
    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(program, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to create process: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <program_to_debug>" << std::endl;
        return 1;
    }

    Debugger debugger;
    if (!debugger.LaunchInferior(argv[1])) {
        return 1;
    }

    debugger.DebuggerEventLoop();
    return 0;
}
