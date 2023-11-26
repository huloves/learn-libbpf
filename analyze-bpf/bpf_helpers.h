#ifndef _BPF_HELPERS_H
#define _BPF_HELPERS_H

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + ((c) > 255 ? 255 : (c)))
#endif

#endif /* _BPF_HELPERS_H */
