int _fltused = 0x9875;

#pragma function(memset)
void *__cdecl memset(void *dst, int val, size_t size) {
    unsigned char  val_u8 = *(unsigned char *)&val;
    unsigned char *dst_u8 =  (unsigned char *)dst;
    while (size--) *dst_u8++ = val_u8;
    return (void *)dst_u8;
}

#pragma function(memcpy)
void *memcpy(void *dst, void *src, size_t count)
{
    unsigned char *src_u8 = (unsigned char *)src;
    unsigned char *dst_u8 = (unsigned char *)dst;
    while (count--) *dst_u8++ = *src_u8++;
    return (void *)dst_u8;
}
