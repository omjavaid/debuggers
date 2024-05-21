#include <iostream>
#include <map>
#include <windows.h>

class Debugger
{
public:
  Debugger() {}

  bool LaunchInferior(const char *program);
  void DebuggerEventLoop();

private:
  void ProcessDebugEvent(const DEBUG_EVENT &debug_event);
  void ProcessCreateEvent(const DEBUG_EVENT &debug_event);
  void ProcessExitEvent(const DEBUG_EVENT &debug_event);
  void ProcessExceptionEvent(const DEBUG_EVENT &debug_event);
  void ProcessOutputStringEvent(const DEBUG_EVENT &debug_event);
  void AddHardwareBreakpoint(void *addr);
  void RemoveBreakpoint(LPVOID breakpointAddress);
  void ProcessCommands();
  void PrintRegs();
  void ReadDebugRegisters();
  void ReadMemory(const char *addr_hex, int n);

  bool cont = true;
  DWORD dwContinueStatus = DBG_CONTINUE;
  CREATE_PROCESS_DEBUG_INFO pInfo = {0};
  PROCESS_INFORMATION pi = {0};
};

void Debugger::AddHardwareBreakpoint(void *addr)
{
  CONTEXT lcContext;
  lcContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (!GetThreadContext(pInfo.hThread, &lcContext))
  {
    printf("GetThreadContext failed: %d\n", GetLastError());
    return;
  }
#if defined(__x86_64__) || defined(_M_X64)
  for (int i = 0; i < 4; i++)
  {
    if ((lcContext.Dr7 & (1 << (2 * i))) == 0)
    {
      // Set breakpoint
      switch (i)
      {
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

      if (!SetThreadContext(pInfo.hThread, &lcContext))
      {
        printf("SetThreadContext failed: %d\n", GetLastError());
        return;
      }
      return;
    }
  }
#elif defined(__aarch64__) || defined(_M_ARM64)
  lcContext.Bvr[0] = (DWORD64)addr;
  lcContext.Bvr[0] &= ~3;
  lcContext.Bcr[0] = (0xfu << 5) | 7;
  if (!SetThreadContext(pInfo.hThread, &lcContext))
  {
    printf("SetThreadContext failed: %d\n", GetLastError());
    return;
  }
  printf("Hardware breakpoint set on addr: 0x%llx\n", lcContext.Bvr[0]);
  return;
#endif
  printf("No available hardware breakpoint slots\n");
}

void Debugger::RemoveBreakpoint(LPVOID breakpointAddress)
{
  CONTEXT lcContext;
  lcContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (!GetThreadContext(pInfo.hThread, &lcContext))
  {
    std::cerr << "GetThreadContext failed: " << GetLastError() << std::endl;
    return;
  }
#if defined(__x86_64__) || defined(_M_X64)
  if (lcContext.Dr0 == reinterpret_cast<DWORD_PTR>(breakpointAddress))
  {
    lcContext.Dr0 = 0;          // Clear the breakpoint address
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
  if (!SetThreadContext(pInfo.hThread, &lcContext))
  {
    std::cerr << "SetThreadContext failed: " << GetLastError() << std::endl;
    return;
  }
#elif defined(__aarch64__) || defined(_M_ARM64)

  if (lcContext.Bvr[0] == (DWORD64)breakpointAddress)
  {
    lcContext.Bcr[0] = 0;
    if (!SetThreadContext(pInfo.hThread, &lcContext))
    {
      printf("SetThreadContext failed: %d\n", GetLastError());
      return;
    }
  }
#endif
}

void Debugger::ProcessExceptionEvent(const DEBUG_EVENT &debug_event)
{
  DWORD code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
  switch (code)
  {
#if defined(__x86_64__) || defined(_M_X64)
  case EXCEPTION_BREAKPOINT:
    dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
#elif defined(__aarch64__) || defined(_M_ARM64)
  case EXCEPTION_SINGLE_STEP:
    std::cout << "Single step exception " << std::endl;
#endif
    break;
#if defined(__x86_64__) || defined(_M_X64)
  case EXCEPTION_SINGLE_STEP:
#elif defined(__aarch64__) || defined(_M_ARM64)
  case EXCEPTION_BREAKPOINT:
#endif
    if (debug_event.u.Exception.dwFirstChance)
    {
      printf("Initial breakpoint exception encountered\n");
      dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
    }
    else
    {
      LPVOID breakpointAddress = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;
      printf("Breakpoint hit at address: %p\n", breakpointAddress);
      RemoveBreakpoint(breakpointAddress);
    }

    break;
  default:
    std::cout << "Exception " << code << " (0x" << std::hex << code << ") received." << std::endl;
    break;
  }
  ProcessCommands();
}

void Debugger::ProcessCreateEvent(const DEBUG_EVENT &debug_event)
{
  pInfo = debug_event.u.CreateProcessInfo;
  std::cout << "Setting a breakpoint at the start address (0x" << std::hex << pInfo.lpStartAddress << ")..." << std::endl;
  AddHardwareBreakpoint(pInfo.lpStartAddress);
}

void Debugger::ProcessExitEvent(const DEBUG_EVENT &debug_event)
{
  std::cout << "Process exited with code (0x" << std::hex << debug_event.u.ExitProcess.dwExitCode << ")." << std::endl;
  cont = false;
}

void Debugger::ProcessDebugEvent(const DEBUG_EVENT &debug_event)
{
  dwContinueStatus = DBG_CONTINUE;
  switch (debug_event.dwDebugEventCode)
  {
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

void Debugger::PrintRegs()
{
  // Read the registers
  CONTEXT lcContext;
  lcContext.ContextFlags = CONTEXT_ALL;
  if (GetThreadContext(pi.hThread, &lcContext))
  {
    // Print out all of the values of the registers
#if defined(__x86_64__) || defined(_M_X64)
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
#elif defined(__aarch64__) || defined(_M_ARM64)
    printf("X0: 0x%llx\n", lcContext.X[0]);
    printf("X1: 0x%llx\n", lcContext.X[1]);
    printf("X2: 0x%llx\n", lcContext.X[2]);
    printf("X3: 0x%llx\n", lcContext.X[3]);
    printf("X4: 0x%llx\n", lcContext.X[4]);
    printf("X5: 0x%llx\n", lcContext.X[5]);
    printf("X6: 0x%llx\n", lcContext.X[6]);
    printf("X7: 0x%llx\n", lcContext.X[7]);
    printf("X8: 0x%llx\n", lcContext.X[8]);
    printf("X9: 0x%llx\n", lcContext.X[9]);
    printf("X10: 0x%llx\n", lcContext.X[10]);
    printf("X11: 0x%llx\n", lcContext.X[11]);
    printf("X12: 0x%llx\n", lcContext.X[12]);
    printf("X13: 0x%llx\n", lcContext.X[13]);
    printf("X14: 0x%llx\n", lcContext.X[14]);
    printf("X15: 0x%llx\n", lcContext.X[15]);
    printf("X16: 0x%llx\n", lcContext.X[16]);
    printf("X17: 0x%llx\n", lcContext.X[17]);
    printf("X18: 0x%llx\n", lcContext.X[18]);
    printf("X19: 0x%llx\n", lcContext.X[19]);
    printf("X20: 0x%llx\n", lcContext.X[20]);
    printf("X21: 0x%llx\n", lcContext.X[21]);
    printf("X22: 0x%llx\n", lcContext.X[22]);
    printf("X23: 0x%llx\n", lcContext.X[23]);
    printf("X24: 0x%llx\n", lcContext.X[24]);
    printf("X25: 0x%llx\n", lcContext.X[25]);
    printf("X26: 0x%llx\n", lcContext.X[26]);
    printf("X27: 0x%llx\n", lcContext.X[27]);
    printf("X28: 0x%llx\n", lcContext.X[28]);
    printf("Fp: 0x%llx\n", lcContext.X[29]);
    printf("Lr: 0x%llx\n", lcContext.X[30]);
    printf("Pc: 0x%llx\n", lcContext.Pc);
    printf("Sp: 0x%llx\n", lcContext.Sp);
#endif
    ReadDebugRegisters();
  }
  else
  {
    std::cerr << "Failed to get thread context: " << GetLastError() << std::endl;
  }
}

void Debugger::ReadDebugRegisters()
{
  // Read the debug registers
  CONTEXT lcContext;
  lcContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
  if (GetThreadContext(pi.hThread, &lcContext))
  {
    // Print out all of the values of the debug registers
#if defined(__x86_64__) || defined(_M_X64)
    std::printf("Dr0: 0x%llx\n", lcContext.Dr0);
    std::printf("Dr1: 0x%llx\n", lcContext.Dr1);
    std::printf("Dr2: 0x%llx\n", lcContext.Dr2);
    std::printf("Dr3: 0x%llx\n", lcContext.Dr3);
    std::printf("Dr6: 0x%llx\n", lcContext.Dr6);
    std::printf("Dr7: 0x%llx\n", lcContext.Dr7);
#elif defined(__aarch64__) || defined(_M_ARM64)
    for (int i = 0; i < ARM64_MAX_BREAKPOINTS; i++)
    {
      // Print out all of the values of the registers
      printf("Bvr %i: 0x%llx\n", i, lcContext.Bvr[i]);
      printf("Bcr %i: 0x%llx\n", i, lcContext.Bcr[i]);
    }
#endif
  }
  else
  {
    std::cerr << "Failed to get debug registers context: " << GetLastError() << std::endl;
  }
}

void Debugger::ProcessCommands()
{
  char cmd[200];

  while (true)
  {
    std::cout << "<dbg> ";
    std::cin.getline(cmd, 200);

    if (strncmp(cmd, "cont", 4) == 0)
    {
      break;
    }
    else if (strncmp(cmd, "regs", 4) == 0)
    {
      PrintRegs();
    }
    else if (strncmp(cmd, "q", 1) == 0)
    {
      std::cout << "Debugger will now exit." << std::endl;
      exit(0);
    }
    else if (strncmp(cmd, "help", 4) == 0)
    {
      std::cout << "cont: Continues execution.\n";
      std::cout << "regs: Prints all registers.\n";
      std::cout << "q: exit debug session.\n";
    }
  }
}

void Debugger::DebuggerEventLoop()
{
  DEBUG_EVENT debug_event = {0};

  while (cont)
  {
    if (!WaitForDebugEvent(&debug_event, INFINITE))
    {
      std::cerr << "WaitForDebugEvent failed: " << GetLastError() << std::endl;
      break;
    }

    ProcessDebugEvent(debug_event);
    ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, dwContinueStatus);
  }

  std::cout << "Debugger will now exit." << std::endl;
}

bool Debugger::LaunchInferior(const char *program)
{
  STARTUPINFO si;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  if (!CreateProcessA(program, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi))
  {
    std::cerr << "Failed to create process: " << GetLastError() << std::endl;
    return false;
  }
  return true;
}

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    std::cerr << "Usage: " << argv[0] << " <program_to_debug>" << std::endl;
    return 1;
  }

  Debugger debugger;
  if (!debugger.LaunchInferior(argv[1]))
  {
    return 1;
  }

  debugger.DebuggerEventLoop();
  return 0;
}
