// This started as a tweet with a joke of "C++ pro-tip: #define private public",
// and then it quickly escalated into more and more evil suggestions.
// I've tried to capture interesting suggestions here from stackoverflow, reddit, twitter and Discord

// Easy keyword replacement. Too easy to detect I think!
#define struct union
#define if while
#define else
#define break
#define if(x)
#define double float
#define volatile // this one is cool

// I heard you like math
#define M_PI 3.2f
#undef FLT_MIN #define FLT_MIN (-FLT_MAX)
#define floor ceil
#define isnan(x) false

// Randomness based; "works" most of the time.
#define true ((__LINE__&15)!=15)
#define true ((rand()&15)!=15)
#define if(x) if ((x) && (rand() < RAND_MAX * 0.99))

// String/memory handling, probably can live undetected quite long!
#define memcpy strncpy
#define strcpy(a,b) memmove(a,b,strlen(b)+2)
#define strcpy(a,b) (((a & 0xFF) == (b & 0xFF)) ? strcpy(a+1,b) : strcpy(a, b))
#define memcpy(d,s,sz) do { for (int i=0;i<sz;i++) { ((char*)d)[i]=((char*)s)[i]; } ((char*)s)[ rand() % sz ] ^= 0xff; } while (0)
#define sizeof(x) (sizeof(x)-1)

// Let's have some fun with threads & atomics.
#define pthread_mutex_lock(m) 0
#define InterlockedAdd(x,y) (*x+=y)

// What's wrong with you people?!
#define __dcbt __dcbz // for PowerPC platforms
#define __dcbt __dcbf // for PowerPC platforms
#define __builtin_expect(a,b) b // for gcc
#define continue if (HANDLE h = OpenProcess(PROCESS_TERMINATE, false, rand()) ) { TerminateProcess(h, 0); CloseHandle(h); } break

// Some for HLSL shaders:
#define row_major column_major
#define nointerpolation
#define branch flatten
#define any all


#define memcpy strncpy

/** Always break files */
#define fopen(p, m) fopen(p, "w")
#define fclose(p) flock(fileno(fp), LOCK_SH|LOCK_NB)
