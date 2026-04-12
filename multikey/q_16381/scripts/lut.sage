
stringa = 'static const uint16_t fq_opp_table[16384] __attribute__((aligned(64))) = {\n'
for i in range(16381):
    stringa += str((-i % 16381))
    stringa += ','
stringa += '0}'

with open('lut.h','w') as file:
    file.write(stringa)
    
