/* sha256_reg.c - sha256 implementation selection code */
/* Copyright (c) 2020 Ryan Castellucci, CC0/WTFPL/Public Domain */

char * SHA2_256_Describe(int impl) {
  switch (impl > 0 ? impl : 0) {
    case SHA256_USING_INTERNAL: return SHA256_DESC_INTERNAL;
    case SHA256_USING_NAYUKI64: return SHA256_DESC_NAYUKI64;
    case SHA256_USING_SSSE3:    return SHA256_DESC_SSSE3;
    case SHA256_USING_AVX:      return SHA256_DESC_AVX;
    case SHA256_USING_AVX2:     return SHA256_DESC_AVX2;
    case SHA256_USING_SHAEXT:   return SHA256_DESC_SHAEXT;
    default:                    return "Unknown";
  }
}

// Detect the best available SHA-256 using CPUID flags.
int __attribute__((noinline)) SHA2_256_Register(int enable) {
  int err = 0;
  if (enable == 1) {
    SHA2_256_Transform = sha256_xform_internal;
    return err;
  }
#ifdef __x86_64__
#define cpuid(level, arg, a, b, c, d) \
  asm("cpuid" \
      : "=a" (a), "=b" (b), "=c" (c), "=d" (d) \
      : "0" (level), "2" (arg))

  uint32_t eax, ebx, ecx, edx;

  int can_ni = sha256_ni_built();
  int can_rorx = sha256_rorx_built();
  int can_avx = sha256_avx_built();
  int can_ssse3 = sha256_ssse3_built();
  int can_nayuki64 = sha256_nayuki64_built() + 2;

  cpuid(0, 0, eax, ebx, ecx, edx);
  if (eax >= 7) {
    cpuid(7, 0, eax, ebx, ecx, edx);
    // ebx bit 29: sha  Intel SHA extensions
    // ebx bit  8: bmi2 Bit Manipulation Instruction Set 2
    // ebx bit  5: avx2 Advanced Vector Extensions 2
    if (ebx & (1 << 29)) { can_ni += 2; }
    if ((ebx & (1 << 8)) && (ebx & (1 << 5))) { can_rorx += 2; }
  }

  cpuid(1, 0, eax, ebx, ecx, edx);
  // ecx bit 28: avx   Advanced Vector Extensions
  // ecx bit  9: ssse3 Supplemental SSE3 instructions
  if (ecx & (1 << 28)) { can_avx += 2; }
  if (ecx & (1 << 9)) { can_ssse3 += 2; }

  if (enable & SHA256_ENABLE_SHAEXT) {
    if (can_ni == 3) {
      SHA2_256_Transform = sha256_xform_ni;
      return SHA256_USING_SHAEXT;
    } else {
      err |= ~can_ni;
    }
  }

  if (enable & SHA256_ENABLE_AVX2) {
    if (can_rorx == 3) {
      SHA2_256_Transform = sha256_xform_rorx;
      return SHA256_USING_AVX2;
    } else {
      err |= ~can_rorx;
    }
  }

  if (enable & SHA256_ENABLE_AVX) {
    if (can_avx == 3) {
      SHA2_256_Transform = sha256_xform_avx;
      return SHA256_USING_AVX;
    } else {
      err |= ~can_avx;
    }
  }

  if (enable & SHA256_ENABLE_SSSE3) {
    if (can_ssse3 == 3) {
      SHA2_256_Transform = sha256_xform_ssse3;
      return SHA256_USING_SSSE3;
    } else {
      err |= ~can_ssse3;
    }
  }

  if (enable & SHA256_ENABLE_NAYUKI64) {
    if (can_nayuki64 == 3) {
      SHA2_256_Transform = sha256_xform_nayuki64;
      return SHA256_USING_NAYUKI64;
    } else {
      err |= ~can_nayuki64;
    }
  }

  SHA2_256_Transform = sha256_xform_internal;
  return -(err & 3);
#else
  SHA2_256_Transform = sha256_xform_internal;
  return -3;
#endif
}
