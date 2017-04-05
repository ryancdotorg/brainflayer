/* sha256_reg.c - sha256 implementation selection code */

// Copyright (C) 2016 Byron Stanoszek  <gandalf@winds.org>
// Copyright (C) 2017 Ryan Castellucci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

// Auto-detect the fastest SHA-256 function to use based on CPUID flags.
int SHA2_256_Register() {
#ifdef __x86_64__
  uint32_t eax, ebx, ecx, edx;

#define cpuid(level, arg, a, b, c, d) \
  asm("cpuid" \
      : "=a" (a), "=b" (b), "=c" (c), "=d" (d) \
      : "0" (level), "2" (arg))

  cpuid(0, 0, eax, ebx, ecx, edx);
  if(eax >= 7) {
    cpuid(7, 0, eax, ebx, ecx, edx);
    if (sha256_ni_built() && ebx & (1 << 29)) {
      sha256_transform_func = sha256_ni_transform;
      return SHA256_USING_SHAEXT;
    } else if (sha256_rorx_built() && (ebx & (1 << 8)) && (ebx & (1 << 5))) {
      sha256_transform_func = sha256_transform_rorx;
      return SHA256_USING_AVX2;
    }
  }

  cpuid(1, 0, eax, ebx, ecx, edx);
  if (sha256_avx_built() && ecx & (1 << 28)) {
    sha256_transform_func = sha256_transform_avx;
    return SHA256_USING_AVX;
  } else if (sha256_ssse3_built() && ecx & (1 << 9)) {
    sha256_transform_func = sha256_transform_ssse3;
    return SHA256_USING_SSSE3;
  }
#endif
  return SHA256_USING_INTERNAL;
}
