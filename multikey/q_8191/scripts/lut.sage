
stringa = 'static const uint16_t fq_inv_table[8192] __attribute__((aligned(64))) = {\n'
for i in range(8191):
    stringa += str((-i % 8191))
    stringa += ','
stringa += '0}'

with open('lut.h','w') as file:
    file.write(stringa)
    
