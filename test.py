def get_bits(bytes):
    bits = []
    for byte in bytes:
        for i in range(7,-1,-1):
            bits.append((byte>>i)&1)

    return bits


integer_val = 5
bytes_val = integer_val.to_bytes(2, 'big')

print(get_bits(bytes_val))

a = {(1,2):[1,2,3], (2,1):[4,5,6], (4,5):[7,8,9]}
b = dict()
v = []

for x,_ in a.items():
    if (x[0], x[1]) not in v or (x[1], x[0]) not in v:
        v += [(x[0], x[1])]
        b[x] = a[x]

print(b)


