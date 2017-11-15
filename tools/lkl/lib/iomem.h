#ifndef _LKL_LIB_IOMEM_H
#define _LKL_LIB_IOMEM_H

struct lkl_iomem_ops {
	int (*read)(void *data, int offset, void *res, int size);
	int (*write)(void *data, int offset, void *value, int size);
};

void* register_iomem(void *data, int size, const struct lkl_iomem_ops *ops);
void unregister_iomem(void *iomem_base);
void *lkl_ioremap(long addr, int size);
int lkl_iomem_read(const volatile void *src, volatile void *dst, int size);
int lkl_iomem_write(volatile void *dst, volatile void *val, int size);

#endif /* _LKL_LIB_IOMEM_H */
