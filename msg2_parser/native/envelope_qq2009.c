/*
 * Standalone port of QQ2009 Common.dll:
 *   sub_60401CF0 (uint32 block cipher round structure per IDA)
 *   sub_60402340 (length envelope / stream decoder)
 *
 * Build (MinGW, 32-bit matches IM/Common builds):
 *   i686-w64-mingw32-gcc -O2 -s envelope_qq2009.c -o envelope_qq2009.exe
 *
 * Run with Wine on Linux.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t qq_u32(uint32_t x) { return x & 0xFFFFFFFFu; }

static uint32_t bswap32(uint32_t x) {
  return ((x & 0xFFu) << 24) | ((x & 0xFF00u) << 8) | ((x & 0xFF0000u) >> 8) |
         ((x & 0xFF000000u) >> 24);
}

static void sub_60401CF0(const uint32_t *a1, const uint8_t *key16, uint32_t *out2) {
  uint32_t v8[4];
  for (int v3 = 0; v3 < 4; ++v3) {
    uint32_t kw;
    memcpy(&kw, key16 + v3 * 4, 4);
    v8[v3] = bswap32(kw);
  }

  uint32_t v4 = bswap32(a1[0]);
  uint32_t v5 = bswap32(a1[1]);
  uint32_t v6 = 0xE3779B90u;
  int v9 = 16;
  do {
    uint32_t t0 = qq_u32(v6 + v4);
    uint32_t t1 = qq_u32(v8[2] + qq_u32(v4 << 4));
    uint32_t t2 = qq_u32(v8[3] + (v4 >> 5));
    uint32_t t3 = qq_u32(t0 ^ qq_u32(t1 ^ t2));
    v5 = qq_u32(v5 - t3);

    uint32_t u0 = qq_u32(v6 + v5);
    uint32_t u1 = qq_u32(v8[0] + qq_u32(v5 << 4));
    uint32_t u2 = qq_u32(v8[1] + (v5 >> 5));
    uint32_t u3 = qq_u32(u0 ^ qq_u32(u1 ^ u2));
    v4 = qq_u32(v4 - u3);

    v6 = qq_u32(v6 + 0x61C88647u);
    --v9;
  } while (v9);

  out2[0] = bswap32(v4);
  out2[1] = bswap32(v5);
}

static int sub_60402340(uint8_t *mem, int a2, const uint8_t *key16, uint8_t *a4,
                        int *a5) {
  int *v5 = a5;
  if (a2 % 8)
    return 0;
  if (a2 < 16)
    return 0;

  uint32_t v27[2];
  uint32_t block0[2];
  memcpy(block0, mem + 8, 8);
  sub_60401CF0(block0, key16, v27);
  memcpy(mem, v27, 8);

  uint32_t v6 = mem[0] & 7;
  int v7 = a2 - (int)v6 - 10;
  if (*v5 < v7 || v7 < 0)
    return 0;
  *v5 = v7;

  uint32_t v26[2] = {0, 0};
  unsigned int *v8 = (unsigned int *)(mem + 8);
  unsigned int *v9 = (unsigned int *)(mem + 16);
  int v10 = (int)v6 + 1;
  int v22 = 8;
  int v23 = 1;
  ptrdiff_t v11 = (uint8_t *)v9 - mem;

  uint32_t *v19 = v26;
  uint8_t *a4p = a4;

label_14:
  while (v10 < 8) {
    ++v10;
    ++v23;
    if (v23 > 2) {
      int v14 = *v5;
      int v18 = v14;
      if (v14) {
        ptrdiff_t v24 = (uint8_t *)v9 - mem;
        do {
          if (v10 >= 8) {
            if (v10 == 8) {
              v19 = v8;
              for (int i = 0; i < 8; ++i) {
                if ((intptr_t)mem + i + v24 + v22 - (intptr_t)v9 >= a2)
                  return 0;
                mem[i] ^= mem[i + v24];
              }
              uint32_t tmp[2];
              memcpy(tmp, mem, 8);
              sub_60401CF0(tmp, key16, (uint32_t *)mem);
              v24 += 8;
              v22 += 8;
              v8 = v9;
              v14 = v18;
              v9 += 2;
              v10 = 0;
            }
          } else {
            uint8_t b = ((uint8_t *)mem)[v10] ^ ((uint8_t *)v19)[v10];
            *a4p++ = b;
            ++v10;
            --v14;
            v18 = v14;
          }
        } while (v14);
      }
      int v25 = 1;
      ptrdiff_t v21 = (uint8_t *)v9 - mem;
      while (1) {
        if (v10 >= 8) {
          if (v10 == 8) {
            v19 = v8;
            int v16 = 0;
            while ((intptr_t)mem + v16 + v21 + v22 - (intptr_t)v9 < a2) {
              mem[v16] ^= mem[v16 + v21];
              if (++v16 >= 8) {
                uint32_t tmp[2];
                memcpy(tmp, mem, 8);
                sub_60401CF0(tmp, key16, (uint32_t *)mem);
                v21 += 8;
                v22 += 8;
                v8 = v9;
                v9 += 2;
                v10 = 0;
                goto label_34;
              }
            }
            return 0;
          }
        } else {
          if (((uint8_t *)mem)[v10] != ((uint8_t *)v19)[v10])
            return 0;
          ++v10;
          ++v25;
        }
      label_34:
        if (v25 > 7)
          return 1;
      }
    }
  }

  if (v10 != 8)
    goto label_14;

  v19 = v8;
  int v12 = 0;
  int j = v22 - (intptr_t)v9;
  for (;;) {
    if (!((intptr_t)mem + v12 + v11 + j < a2))
      break;
    mem[v12] ^= mem[v12 + v11];
    if (++v12 >= 8) {
      uint32_t tmp[2];
      memcpy(tmp, mem, 8);
      sub_60401CF0(tmp, key16, (uint32_t *)mem);
      v22 += 8;
      v8 = v9;
      v9 += 2;
      v11 += 8;
      v10 = 0;
      goto label_14;
    }
  }
  return 0;
}

static int hexparse(const char *s, uint8_t *buf, size_t maxlen, size_t *outlen) {
  size_t n = strlen(s);
  if (n % 2)
    return -1;
  if (n / 2 > maxlen)
    return -1;
  for (size_t i = 0; i < n / 2; ++i) {
    char tmp[3] = {s[i * 2], s[i * 2 + 1], 0};
    unsigned int v;
    if (sscanf(tmp, "%02x", &v) != 1)
      return -1;
    buf[i] = (uint8_t)v;
  }
  *outlen = n / 2;
  return 0;
}

/*
 * argv: envelope_qq2009.exe <key_hex32> <cipher_body_hex>
 * cipher_body = ITXBuffer payload **without** leading 0x01 version byte.
 */
int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "usage: %s <key_hex32> <cipher_hex>\n", argv[0]);
    return 2;
  }
  uint8_t key[16];
  size_t kl;
  if (hexparse(argv[1], key, sizeof key, &kl) || kl != 16) {
    fprintf(stderr, "bad key\n");
    return 2;
  }
  uint8_t buf[65536];
  size_t bl;
  if (hexparse(argv[2], buf, sizeof buf, &bl)) {
    fprintf(stderr, "bad cipher hex\n");
    return 2;
  }
  if (bl > sizeof(buf) - 8 || bl < 16 || bl % 8) {
    fprintf(stderr, "bad cipher length\n");
    return 2;
  }

  uint8_t mem[8 + 65536];
  memset(mem, 0, sizeof mem);
  memcpy(mem + 8, buf, bl);

  uint8_t plain[65536];
  int cap = (int)sizeof plain;
  int rc = sub_60402340(mem, bl, key, plain, &cap);
  if (!rc) {
    fprintf(stderr, "decrypt_fail rc=0 cap=%d\n", cap);
    return 1;
  }
  fwrite(plain, 1, (size_t)cap, stdout);
  return 0;
}
