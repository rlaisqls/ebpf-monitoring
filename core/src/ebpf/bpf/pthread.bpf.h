

#ifndef IWMEBPF_PTHREAD_BPF_H
#define IWMEBPF_PTHREAD_BPF_H




#if defined(__TARGET_ARCH_x86)

#include "pthread_amd64.h"

#elif defined(__TARGET_ARCH_arm64)

#include "pthread_arm64.h"

#else

#error "Unknown architecture"

#endif



#endif //IWMEBPF_PTHREAD_BPF_H
