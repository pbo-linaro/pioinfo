#define _CRT_SECURE_NO_WARNINGS

#include <cstdint>
#include <cstdio>
#include <cassert>
#include <iostream>

#include <fcntl.h>
#include <io.h>
#include <windows.h>
#include <psapi.h>

void* dll_base_address;

template <typename T>
static uint64_t offset(T* addr)
{
    return (uint8_t*)addr - (uint8_t*)dll_base_address;
}

#define RUBY_MSVCRT_VERSION 200

/* License: Ruby's */
static FARPROC get_proc_address(const char *module, const char *func,
                                HANDLE *mh) {
  HMODULE h;
  FARPROC ptr;

  if (mh)
    h = LoadLibrary(module);
  else
    h = GetModuleHandle(module);
  if (!h)
    return NULL;

  char buffer[1024];
  auto wrote = GetModuleFileName(h, buffer, 1024);
  assert(wrote > 0);

  MODULEINFO modinfo;
  auto res = GetModuleInformation(GetCurrentProcess(), h, &modinfo, sizeof(MODULEINFO));
  assert(res != 0);
  dll_base_address = modinfo.lpBaseOfDll;

  std::cout << "DLL: " << buffer << " | loaded at 0x" << std::hex <<
      dll_base_address << '\n';

  ptr = GetProcAddress(h, func);

  std::cout << func << ": 0x" << std::hex << ptr << '\n';
  std::cout << func << " offset:" << "0x" << std::hex << offset(ptr) << '\n';

  if (mh) {
    if (ptr)
      *mh = h;
    else
      FreeLibrary(h);
  }
  return ptr;
}

#if RUBY_MSVCRT_VERSION >= 140
typedef char lowio_text_mode;
typedef char lowio_pipe_lookahead[3];

typedef struct {
  CRITICAL_SECTION lock;
  intptr_t osfhnd;      // underlying OS file HANDLE
  __int64 startpos;     // File position that matches buffer start
  unsigned char osfile; // Attributes of file (e.g., open in text mode?)
  lowio_text_mode textmode;
  lowio_pipe_lookahead _pipe_lookahead;

  uint8_t unicode : 1;          // Was the file opened as unicode?
  uint8_t utf8translations : 1; // Buffer contains translations other than CRLF
  uint8_t dbcsBufferUsed : 1;   // Is the dbcsBuffer in use?
  char dbcsBuffer; // Buffer for the lead byte of DBCS when converting from DBCS
                   // to Unicode
} ioinfo;
#else
typedef struct {
  intptr_t osfhnd; /* underlying OS file HANDLE */
  char osfile;     /* attributes of file (e.g., open in text mode?) */
  char pipech;     /* one char buffer for handles opened on pipes */
  int lockinitflag;
  CRITICAL_SECTION lock;
#if RUBY_MSVCRT_VERSION >= 80
  char textmode;
  char pipech2[2];
#endif
} ioinfo;
#endif

#if !defined _CRTIMP || defined __MINGW32__
#undef _CRTIMP
#define _CRTIMP __declspec(dllimport)
#endif

#if RUBY_MSVCRT_VERSION >= 140
static ioinfo **__pioinfo = NULL;
#define IOINFO_L2E 6
#else
extern "C" _CRTIMP ioinfo *__pioinfo[];
#define IOINFO_L2E 5
#endif
static inline ioinfo *_pioinfo(int);

#define IOINFO_ARRAY_ELTS (1 << IOINFO_L2E)
#define _osfhnd(i) (_pioinfo(i)->osfhnd)
#define _osfile(i) (_pioinfo(i)->osfile)
#define rb_acrt_lowio_lock_fh(i) EnterCriticalSection(&_pioinfo(i)->lock)
#define rb_acrt_lowio_unlock_fh(i) LeaveCriticalSection(&_pioinfo(i)->lock)

#if RUBY_MSVCRT_VERSION >= 80
static size_t pioinfo_extra = 0; /* workaround for VC++8 SP1 */

/* License: Ruby's */
static void set_pioinfo_extra(void) {
#if RUBY_MSVCRT_VERSION >= 140
#define FUNCTION_RET 0xc3

#ifdef _DEBUG
#define UCRTBASE "ucrtbased.dll"
#else
#define UCRTBASE "ucrtbase.dll"
#endif
  /* get __pioinfo addr with _isatty */
  /*
   * Why Ruby depends to _pioinfo is
   * * to associate socket and fd: CRuby creates fd with dummy file handle
   *   and set socket to emulate Unix-like behavior. Without __pioinfo
   *   we need something which manages the fd number allocation
   * * to implement overlapped I/O for Windows 2000/XP
   * * to emulate fcntl(2)
   *
   * see also
   * * https://bugs.ruby-lang.org/issues/11118
   * * https://bugs.ruby-lang.org/issues/18605
   */
  char *p = (char *)get_proc_address(UCRTBASE, "_isatty", NULL);
  /* _osfile(fh) & FDEV */

#ifdef _M_ARM64
#define IS_INSN(pc, name) ((*(pc) & name##_mask) == name##_id)
  const int max_num_inst = 500;
  uint32_t* start = (uint32_t*)p;
  uint32_t* end_limit = (start + max_num_inst);
  uint32_t* pc = start;

  if (!p) {
    fprintf(stderr, "_isatty proc not found in " UCRTBASE "\n");
    _exit(1);
  }

  /* end of function */
  const uint32_t ret_id= 0xd65f0000;
  const uint32_t ret_mask = 0xfffffc1f;
  for(; pc < end_limit; pc++) {
      if (IS_INSN(pc, ret)) {
          break;
      }
  }
  if (pc == end_limit) {
    fprintf(stderr, "end of _isatty not found in " UCRTBASE "\n");
    _exit(1);
  }
  std::cout << "end is " << std::hex << offset(pc) << '\n';

  /* pioinfo instruction mark */
  const uint32_t adrp_id = 0x90000000;
  const uint32_t adrp_mask = 0x9f000000;
  const uint32_t add_id = 0x11000000;
  const uint32_t add_mask = 0x3fc00000;
  for(; pc > start; pc--) {
      if (IS_INSN(pc, adrp) && IS_INSN(pc + 1, add)) {
          break;
      }
  }
  if(pc == start) {
    fprintf(stderr, "pioinfo mark not found in " UCRTBASE "\n");
    _exit(1);
  }

  /* We now point to instructions that load address of __pioinfo:
   * adrp	x8, 0x1801d8000
   * add	x8, x8, #0xdb0
   * https://devblogs.microsoft.com/oldnewthing/20220809-00/?p=106955
   */
  const uint32_t adrp_insn = *pc;
  const uint32_t adrp_immhi = (adrp_insn & 0x00ffffe0) >> 5;
  const uint32_t adrp_immlo = (adrp_insn & 0x60000000) >> (5 + 19 + 5);
  /* imm = immhi:immlo:Zeros(12), 64 */
  const uint64_t adrp_imm = ((adrp_immhi << 2) | adrp_immlo) << 12;
  /* base = PC64<63:12>:Zeros(12) */
  const uint64_t adrp_base = (uint64_t)pc & 0xfffffffffffff000;

  const uint32_t add_insn = *(pc + 1);
  const uint32_t add_sh = (add_insn & 0x400000) >> (12 + 5 + 5);
  /* case sh of
    when '0' imm = ZeroExtend(imm12, datasize);
    when '1' imm = ZeroExtend(imm12:Zeros(12), datasize); */
  const uint64_t add_imm = ((add_insn & 0x3ffc00) >> (5 + 5)) << (add_sh ? 12 : 0);

  __pioinfo = (ioinfo**)(adrp_base + adrp_imm + add_imm);
#else /* _M_ARM64 */
  char *pend = p;
#if defined _WIN64
  int32_t rel;
  char *rip;
  /* add rsp, _ */
#define FUNCTION_BEFORE_RET_MARK "\x48\x83\xc4"
#define FUNCTION_SKIP_BYTES 1
#define FUNCTION_MAX_LENGTH 300
#ifdef _DEBUG
  /* lea rcx,[__pioinfo's addr in RIP-relative 32bit addr] */
#define PIOINFO_MARK "\x48\x8d\x0d"
#else /* x86 */
  /* lea rdx,[__pioinfo's addr in RIP-relative 32bit addr] */
#define PIOINFO_MARK "\x48\x8d\x15"
#endif

#else /* x86 */
  /* pop ebp */
#define FUNCTION_BEFORE_RET_MARK "\x5d"
  /* leave */
#define FUNCTION_BEFORE_RET_MARK_2 "\xc9"
#define FUNCTION_SKIP_BYTES 0
#define FUNCTION_MAX_LENGTH 300
  /* mov eax,dword ptr [eax*4+100EB430h] */
#define PIOINFO_MARK "\x8B\x04\x85"
#endif
  assert(p);
  if (p) {
    for (pend += 10; pend < p + FUNCTION_MAX_LENGTH; pend++) {
      // find end of function
      if ((memcmp(pend, FUNCTION_BEFORE_RET_MARK,
                  sizeof(FUNCTION_BEFORE_RET_MARK) - 1) == 0
#ifdef FUNCTION_BEFORE_RET_MARK_2
           || memcmp(pend, FUNCTION_BEFORE_RET_MARK_2,
                     sizeof(FUNCTION_BEFORE_RET_MARK_2) - 1) == 0
#endif
           ) &&
          *(pend + (sizeof(FUNCTION_BEFORE_RET_MARK) - 1) +
            FUNCTION_SKIP_BYTES) == (char)FUNCTION_RET) {
        std::cout << "end of symbol isatty at: 0x" << std::hex << offset(pend) << '\n';
        // search backwards from end of function
#ifdef _M_ARM64
#else
        for (pend -= (sizeof(PIOINFO_MARK) - 1); pend > p; pend--) {
          if (memcmp(pend, PIOINFO_MARK, sizeof(PIOINFO_MARK) - 1) == 0) {
            p = pend;
            goto found;
          }
        }
        break;
#endif
      }
    }
  }
  fprintf(stderr, "unexpected " UCRTBASE "\n");
  _exit(1);

found:
  std::cout << "found pinfo mark at: 0x" << std::hex << offset(p) << '\n';
  p += sizeof(PIOINFO_MARK) - 1;
#ifdef _M_ARM64
#elif defined _WIN64
  rel = *(int32_t *)(p);
  std::cout << "pointer on pioinfo: 0x" << std::hex << *(int32_t*)p << '\n';
  rip = p + sizeof(int32_t);
  __pioinfo = (ioinfo **)(rip + rel);
  std::cout << "pioinfo offset: 0x" << offset(__pioinfo) << '\n';
#else /* x86 */
  __pioinfo = *(ioinfo ***)(p);
#endif
#endif /* _M_ARM64 */
#endif /* RUBY_MSVCRT_VERSION */
  int fd;

  fd = _open("NUL", O_RDONLY);
  for (pioinfo_extra = 0; pioinfo_extra <= 64;
       pioinfo_extra += sizeof(void *)) {
    if (_osfhnd(fd) == _get_osfhandle(fd)) {
      break;
    }
  }
  _close(fd);

  if (pioinfo_extra > 64) {
    /* not found, maybe something wrong... */
    std::cout << "pioinfo_extra not found\n";
    _exit(1);
    pioinfo_extra = 0;
  }

  std::cout << "pioinfo_extra: " << pioinfo_extra << '\n';
}
#else
#define pioinfo_extra 0
#endif

static inline ioinfo *_pioinfo(int fd) {
  const size_t sizeof_ioinfo = sizeof(ioinfo) + pioinfo_extra;
  return (ioinfo *)((char *)__pioinfo[fd >> IOINFO_L2E] +
                    (fd & (IOINFO_ARRAY_ELTS - 1)) * sizeof_ioinfo);
}

int main() { set_pioinfo_extra(); }
