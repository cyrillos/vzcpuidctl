#ifndef VZCPUIDCTL_BASE64_H__
#define VZCPUIDCTL_BASE64_H__

extern size_t b64_encoded_size(size_t inlen);
extern char *b64_encode(const unsigned char *in, size_t len);

extern size_t b64_decoded_size(const char *in);
extern int b64_decode(const char *in, unsigned char *out, size_t outlen);

#endif /* VZCPUIDCTL_BASE64_H__ */
