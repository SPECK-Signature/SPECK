# djbsort at version 20190516

## install

Download and unzip djbsort package following the instructions at https://sorting.cr.yp.to/install.html 
Then, from the djbsort-20190516 directory, type the following commands: 

```bash
PERK_DIR=</full/path/to/perk/project/directory>
mkdir -p $PERK_DIR/lib/djbsort/avx2
cp int32/avx2/sort.c $PERK_DIR/lib/djbsort/avx2/sort.c
cp h-internal/int32_minmax_x86.c  $PERK_DIR/lib/djbsort/avx2/int32_minmax_x86.inc
mkdir -p $PERK_DIR/lib/djbsort/opt64
cp int32/portable4/sort.c $PERK_DIR/lib/djbsort/opt64/sort.c
cp h-internal/int32_minmax.c $PERK_DIR/lib/djbsort/opt64/int32_minmax.inc
cp uint32/useint32/sort.c  $PERK_DIR/lib/djbsort/djbsort.c
```

Change directory to the perk project and apply the following patch:

```patch
diff --git a/lib/djbsort/avx2/int32_minmax_x86.inc b/lib/djbsort/avx2/int32_minmax_x86.inc
index c5f3006..ffc177f 100644
--- a/lib/djbsort/avx2/int32_minmax_x86.inc
+++ b/lib/djbsort/avx2/int32_minmax_x86.inc
@@ -1,7 +1,7 @@
 #define int32_MINMAX(a,b) \
 do { \
   int32 temp1; \
-  asm( \
+  __asm__( \
     "cmpl %1,%0\n\t" \
     "mov %0,%2\n\t" \
     "cmovg %1,%0\n\t" \
diff --git a/lib/djbsort/avx2/sort.c b/lib/djbsort/avx2/sort.c
index ca81bf6..675cecf 100644
--- a/lib/djbsort/avx2/sort.c
+++ b/lib/djbsort/avx2/sort.c
@@ -1,8 +1,8 @@
-#include "int32_sort.h"
+#include "djbsort.h"
 #define int32 int32_t
 
 #include <immintrin.h>
-#include "int32_minmax_x86.c"
+#include "int32_minmax_x86.inc"
 
 typedef __m256i int32x8;
 #define int32x8_load(z) _mm256_loadu_si256((__m256i *) (z))
@@ -18,7 +18,7 @@ do { \
 } while(0)
 
 __attribute__((noinline))
-static void minmax_vector(int32 *x,int32 *y,long long n)
+static void minmax_vector(int32 *x,int32 *y,size_t n)
 {
   if (n < 8) {
     while (n > 0) {
@@ -93,9 +93,9 @@ static void merge16_finish(int32 *x,int32x8 x0,int32x8 x1,int flagdown)
 
 /* stages 64,32 of bitonic merging; n is multiple of 128 */
 __attribute__((noinline))
-static void int32_twostages_32(int32 *x,long long n)
+static void int32_twostages_32(int32 *x,size_t n)
 {
-  long long i;
+  size_t i;
 
   while (n > 0) {
     for (i = 0;i < 32;i += 8) {
@@ -121,9 +121,9 @@ static void int32_twostages_32(int32 *x,long long n)
 
 /* stages 4q,2q,q of bitonic merging */
 __attribute__((noinline))
-static long long int32_threestages(int32 *x,long long n,long long q)
+static size_t int32_threestages(int32 *x,size_t n,size_t q)
 {
-  long long k,i;
+  size_t k,i;
 
   for (k = 0;k + 8*q <= n;k += 8*q)
     for (i = k;i < k + q;i += 8) {
@@ -164,8 +164,8 @@ static long long int32_threestages(int32 *x,long long n,long long q)
 
 /* n is a power of 2; n >= 8; if n == 8 then flagdown */
 __attribute__((noinline))
-static void int32_sort_2power(int32 *x,long long n,int flagdown)
-{ long long p,q,i,j,k;
+static void int32_sort_2power(int32 *x,size_t n,int flagdown)
+{ size_t p,q,i,j,k;
   int32x8 mask;
 
   if (n == 8) {
@@ -876,8 +876,8 @@ static void int32_sort_2power(int32 *x,long long n,int flagdown)
   }
 }
 
-void int32_sort(int32 *x,long long n)
-{ long long q,i,j;
+void int32_sort(int32 *x,size_t n)
+{ size_t q,i,j;
 
   if (n <= 8) {
     if (n == 8) {
diff --git a/lib/djbsort/djbsort.c b/lib/djbsort/djbsort.c
index b11ed55..62e49c5 100644
--- a/lib/djbsort/djbsort.c
+++ b/lib/djbsort/djbsort.c
@@ -1,12 +1,11 @@
-#include "int32_sort.h"
-#include "uint32_sort.h"
+#include "djbsort.h"
 
 /* can save time by vectorizing xor loops */
 /* can save time by integrating xor loops with int32_sort */
 
-void uint32_sort(uint32_t *x,long long n)
+void uint32_sort(uint32_t *x,size_t n)
 {
-  long long j;
+  size_t j;
   for (j = 0;j < n;++j) x[j] ^= 0x80000000;
   int32_sort((int32_t *) x,n);
   for (j = 0;j < n;++j) x[j] ^= 0x80000000;
diff --git a/lib/djbsort/djbsort.h b/lib/djbsort/djbsort.h
new file mode 100644
index 0000000..92f5164
--- /dev/null
+++ b/lib/djbsort/djbsort.h
@@ -0,0 +1,16 @@
+
+/**
+ * @file djbsort.h
+ * @brief Header file for sorting functions
+ */
+
+#ifndef DJB_SORT_H
+#define DJB_SORT_H
+
+#include <stdint.h>
+#include <stddef.h>
+
+extern void uint32_sort(uint32_t *, size_t) __attribute__((visibility("default")));
+extern void int32_sort(int32_t *, size_t) __attribute__((visibility("default")));
+
+#endif
diff --git a/lib/djbsort/opt64/sort.c b/lib/djbsort/opt64/sort.c
index 511e98a..f2d7c29 100644
--- a/lib/djbsort/opt64/sort.c
+++ b/lib/djbsort/opt64/sort.c
@@ -1,11 +1,11 @@
-#include "int32_sort.h"
+#include "djbsort.h"
 #define int32 int32_t
 
-#include "int32_minmax.c"
+#include "int32_minmax.inc"
 
-void int32_sort(int32 *x,long long n)
+void int32_sort(int32 *x,size_t n)
 {
-  long long top,p,q,r,i,j;
+  size_t top,p,q,r,i,j;
 
   if (n < 2) return;
   top = 1;
```


