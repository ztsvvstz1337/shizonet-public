#ifndef OSCPP_ENDIAN_HPP_INCLUDED
#define OSCPP_ENDIAN_HPP_INCLUDED

#define OSCPP_BYTE_ORDER_BIG_ENDIAN 4321
#define OSCPP_BYTE_ORDER_LITTLE_ENDIAN 1234

// GNU libc provides <endian.h>
#if defined(__GLIBC__) || defined(__ANDROID__)
#    include <endian.h>
#    if (__BYTE_ORDER == __LITTLE_ENDIAN)
#        define OSCPP_LITTLE_ENDIAN
#    elif (__BYTE_ORDER == __BIG_ENDIAN)
#        define OSCPP_BIG_ENDIAN
#    else
#        define OSCPP_LITTLE_ENDIAN // Fallback
#    endif
#    define OSCPP_BYTE_ORDER __BYTE_ORDER

// Explicit endian macros
#elif defined(_BIG_ENDIAN) && !defined(_LITTLE_ENDIAN) ||     \
      defined(__BIG_ENDIAN__) && !defined(__LITTLE_ENDIAN__) || \
      defined(_STLP_BIG_ENDIAN) && !defined(_STLP_LITTLE_ENDIAN)
#    define OSCPP_BIG_ENDIAN
#    define OSCPP_BYTE_ORDER OSCPP_BYTE_ORDER_BIG_ENDIAN

#elif defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN) ||     \
      defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__) || \
      defined(_STLP_LITTLE_ENDIAN) && !defined(_STLP_BIG_ENDIAN)
#    define OSCPP_LITTLE_ENDIAN
#    define OSCPP_BYTE_ORDER OSCPP_BYTE_ORDER_LITTLE_ENDIAN

// Big-endian architectures
#elif defined(__sparc) || defined(__sparc__) || defined(_POWER) || \
      defined(__powerpc__) || defined(__ppc__) || defined(__hpux) || \
      defined(__hppa) || defined(_MIPSEB) || defined(__s390__)
#    define OSCPP_BIG_ENDIAN
#    define OSCPP_BYTE_ORDER OSCPP_BYTE_ORDER_BIG_ENDIAN

// Little-endian architectures
#elif defined(__i386__) || defined(__alpha__) || defined(__ia64) ||  \
      defined(__ia64__) || defined(_M_IX86) || defined(_M_IA64) ||   \
      defined(_M_ALPHA) || defined(__amd64) || defined(__amd64__) || \
      defined(_M_AMD64) || defined(__x86_64) || defined(__x86_64__) || \
      defined(_M_X64) || defined(__bfin__) || defined(__EMSCRIPTEN__)
#    define OSCPP_LITTLE_ENDIAN
#    define OSCPP_BYTE_ORDER OSCPP_BYTE_ORDER_LITTLE_ENDIAN

// Arduino/Embedded: ARM Cortex-M
#elif defined(__arm__) || defined(__ARMEL__) || defined(__ARM_ARCH) || \
      defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_6M__)
#    define OSCPP_LITTLE_ENDIAN
#    define OSCPP_BYTE_ORDER OSCPP_BYTE_ORDER_LITTLE_ENDIAN

// ESP32 / ESP8266
#elif defined(ESP32) || defined(ESP8266)
#    define OSCPP_LITTLE_ENDIAN
#    define OSCPP_BYTE_ORDER OSCPP_BYTE_ORDER_LITTLE_ENDIAN

// DEFAULT FALLBACK: assume little-endian
#else
#    warning "Unknown architecture: defaulting to little-endian."
#    define OSCPP_LITTLE_ENDIAN
#    define OSCPP_BYTE_ORDER OSCPP_BYTE_ORDER_LITTLE_ENDIAN
#endif

#endif // OSCPP_ENDIAN_HPP_INCLUDED
