/* License: Ruby's */
#if RUBY_MSVCRT_VERSION >= 140
typedef char lowio_text_mode;
typedef char lowio_pipe_lookahead[3];

typedef struct {
    CRITICAL_SECTION           lock;
    intptr_t                   osfhnd;          // underlying OS file HANDLE
    __int64                    startpos;        // File position that matches buffer start
    unsigned char              osfile;          // Attributes of file (e.g., open in text mode?)
    lowio_text_mode            textmode;
    lowio_pipe_lookahead       _pipe_lookahead;

    uint8_t unicode          : 1; // Was the file opened as unicode?
    uint8_t utf8translations : 1; // Buffer contains translations other than CRLF
    uint8_t dbcsBufferUsed   : 1; // Is the dbcsBuffer in use?
    char    dbcsBuffer;           // Buffer for the lead byte of DBCS when converting from DBCS to Unicode
} ioinfo;
#else
typedef struct	{
    intptr_t osfhnd;	/* underlying OS file HANDLE */
    char osfile;	/* attributes of file (e.g., open in text mode?) */
    char pipech;	/* one char buffer for handles opened on pipes */
    int lockinitflag;
    CRITICAL_SECTION lock;
#if RUBY_MSVCRT_VERSION >= 80
    char textmode;
    char pipech2[2];
#endif
}	ioinfo;
#endif

#if !defined _CRTIMP || defined __MINGW32__
#undef _CRTIMP
#define _CRTIMP __declspec(dllimport)
#endif

#if RUBY_MSVCRT_VERSION >= 140
static ioinfo ** __pioinfo = NULL;
#define IOINFO_L2E 6
#else
extern "C" _CRTIMP ioinfo * __pioinfo[];
#define IOINFO_L2E 5
#endif
static inline ioinfo* _pioinfo(int);


#define IOINFO_ARRAY_ELTS	(1 << IOINFO_L2E)
#define _osfhnd(i)  (_pioinfo(i)->osfhnd)
#define _osfile(i)  (_pioinfo(i)->osfile)
#define rb_acrt_lowio_lock_fh(i)   EnterCriticalSection(&_pioinfo(i)->lock)
#define rb_acrt_lowio_unlock_fh(i) LeaveCriticalSection(&_pioinfo(i)->lock)

#if RUBY_MSVCRT_VERSION >= 80
static size_t pioinfo_extra = 0;	/* workaround for VC++8 SP1 */

/* License: Ruby's */
static void
set_pioinfo_extra(void)
{
#if RUBY_MSVCRT_VERSION >= 140
# define FUNCTION_RET 0xc3 /* ret */
# ifdef _DEBUG
#  define UCRTBASE "ucrtbased.dll"
# else
#  define UCRTBASE "ucrtbase.dll"
# endif
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
    char *p = (char*)get_proc_address(UCRTBASE, "_isatty", NULL);
    char *pend = p;
    /* _osfile(fh) & FDEV */

# ifdef _WIN64
    int32_t rel;
    char *rip;
    /* add rsp, _ */
#  define FUNCTION_BEFORE_RET_MARK "\x48\x83\xc4"
#  define FUNCTION_SKIP_BYTES 1
#  ifdef _DEBUG
    /* lea rcx,[__pioinfo's addr in RIP-relative 32bit addr] */
#   define PIOINFO_MARK "\x48\x8d\x0d"
#  else
    /* lea rdx,[__pioinfo's addr in RIP-relative 32bit addr] */
#   define PIOINFO_MARK "\x48\x8d\x15"
#  endif

# else /* x86 */
    /* pop ebp */
#  define FUNCTION_BEFORE_RET_MARK "\x5d"
    /* leave */
#  define FUNCTION_BEFORE_RET_MARK_2 "\xc9"
#  define FUNCTION_SKIP_BYTES 0
    /* mov eax,dword ptr [eax*4+100EB430h] */
#  define PIOINFO_MARK "\x8B\x04\x85"
# endif
    if (p) {
        for (pend += 10; pend < p + 500; pend++) {
            // find end of function
            if ((memcmp(pend, FUNCTION_BEFORE_RET_MARK, sizeof(FUNCTION_BEFORE_RET_MARK) - 1) == 0
# ifdef FUNCTION_BEFORE_RET_MARK_2
                || memcmp(pend, FUNCTION_BEFORE_RET_MARK_2, sizeof(FUNCTION_BEFORE_RET_MARK_2) - 1) == 0
# endif
                ) &&
                *(pend + (sizeof(FUNCTION_BEFORE_RET_MARK) - 1) + FUNCTION_SKIP_BYTES) == (char)FUNCTION_RET) {
                // search backwards from end of function
                for (pend -= (sizeof(PIOINFO_MARK) - 1); pend > p; pend--) {
                    if (memcmp(pend, PIOINFO_MARK, sizeof(PIOINFO_MARK) - 1) == 0) {
                        p = pend;
                        goto found;
                    }
                }
                break;
            }
        }
    }
    fprintf(stderr, "unexpected " UCRTBASE "\n");
    _exit(1);

    found:
    p += sizeof(PIOINFO_MARK) - 1;
#ifdef _WIN64
    rel = *(int32_t*)(p);
    rip = p + sizeof(int32_t);
    __pioinfo = (ioinfo**)(rip + rel);
#else
    __pioinfo = *(ioinfo***)(p);
#endif
#endif
    int fd;

    fd = _open("NUL", O_RDONLY);
    for (pioinfo_extra = 0; pioinfo_extra <= 64; pioinfo_extra += sizeof(void *)) {
        if (_osfhnd(fd) == _get_osfhandle(fd)) {
            break;
        }
    }
    _close(fd);

    if (pioinfo_extra > 64) {
        /* not found, maybe something wrong... */
        pioinfo_extra = 0;
    }
}
#else
#define pioinfo_extra 0
#endif
