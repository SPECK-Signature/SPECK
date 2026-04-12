
#bits in first index
b1 = 0
#bits in second index
b2 = 0


a = 16
for i in range(16):
    print(f"=====CASE {i} ======")
    if a < 14:
        b1 = a
        print(f"b1 = {b1} (shift right by {(16 - a) % 16})")
        b2 = 14 - b1
        print(f"b2 = {b2} (shift left by {14-b2})")
        a = 16 - b2
    else:
        b1 = 14
        print(f"b1 = {b1} (shift right by {(16 - a) % 16})")
        b2 = 0
        print(f"b2 = {0}")
        a = a - 14
    if a == 0:
        a = 16
