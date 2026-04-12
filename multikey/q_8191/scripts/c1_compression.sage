
#bits in first index
b1 = 0
#bits in second index
b2 = 0


a = 16
for i in range(16):
    print(f"=====CASE {i} ======")
    if a < 13:
        b1 = a
        print(f"b1 = {b1} (shift left by {(16 - a) % 16})")
        b2 = 13 - b1
        print(f"b2 = {b2} (shift right by {13-b2})")
        a = 16 - b2
    else:
        b1 = 13
        print(f"b1 = {b1} (shift left by {(16 - a) % 16})")
        b2 = 0
        print(f"b2 = {0}")
        a = a - 13
    if a == 0:
        a = 16
