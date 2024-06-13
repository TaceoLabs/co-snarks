from sage.all import *
import random

P = 0x2523648240000001BA344D80000000086121000000000013A700000000000013
P_LEN = len(P.bits())
assert(254 == P_LEN)


def rand():
    return random.randrange(P) # not crypto secure

def to_bits(x):
    return [int(y) for y in reversed(bin(x)[2:].zfill(254))]

def from_bits(x):
    length = len(x)
    return sum([x[i] * 2^i for i in range(length)])

def shift_left(x, n):
    return [0]*n + x[:-n]

def shift_right(x, n):
    return x[n:]

def kogge_add_2(a, b):
    length = len(a)
    assert(length == len(b))

    p = []
    g = []
    for i in range(length):
        p.append(a[i] ^^ b[i])
        g.append(a[i] & b[i])
    s_ = p.copy()

    d = int(ceil(log(length, 2)))

    for i in range(0, d):
        shift = 1 << i
        p_ = shift_left(p.copy(), shift)
        g_ = shift_left(g.copy(), shift)


        for j in range(length):
            g_[j] = g_[j] & p[j]
            p[j] = p_[j] & p[j]
            g[j] = g[j] ^^ g_[j]

    g = [0] + g[:]
    for i in range(length):
        g[i] = s_[i] ^^ g[i]
    return g


def kogge_add_2_v2(a, b):
    length = len(a)
    assert(length == len(b))

    p = []
    g = []
    for i in range(length):
        p.append(a[i] ^^ b[i])
        g.append(a[i] & b[i])
    s_ = p.copy()

    d = int(ceil(log(length, 2)))

    for i in range(0, d):
        shift = 1 << i

        p_ = p[:-shift].copy()
        g_ = g[:-shift].copy()

        p_shift = shift_right(p, shift)

        for j in range(shift):
            p[j] = 0
        for j in range(0, len(p_)):
            g_[j] = g_[j] & p_shift[j]
            p[j + shift] = p_[j] & p_shift[j]
            g[j + shift] = g[j + shift] ^^ g_[j]

    g = [0] + g[:]
    for i in range(length):
        g[i] = s_[i] ^^ g[i]
    return g

def kogge_sub_p(a):
    length = len(a)
    a_ = copy(a)
    a_.pop()
    new_len = len(a_)
    b_ = (1 << (new_len+1)) - P
    b_ = [int(y) for y in reversed(bin(b_)[2:].zfill(length))]
    while len(b_) > new_len:
        b_.pop()
    sub = kogge_add_2_v2(a_, b_)
    ov = sub[new_len] ^^ a[new_len]
    return (sub[:new_len], ov)

def kogge_sub(a, b):
    length = len(a)
    assert(length == len(b))

    # two's complement of b:
    # invert each bit and set cin to 1
    for i in range(length):
        b[i] = b[i] ^^ 1

    p = []
    g = []
    for i in range(length):
        p.append(a[i] ^^ b[i])
        g.append(a[i] & b[i])
    s_ = p.copy()
    # cin = 1:
    g[0] = g[0] ^^ p[0]

    d = int(ceil(log(length, 2)))

    for i in range(0, d):
        shift = 1 << i

        p_ = p[:-shift].copy()
        g_ = g[:-shift].copy()

        p_shift = shift_right(p, shift)

        for j in range(shift):
            p[j] = 0
        for j in range(0, len(p_)):
            g_[j] = g_[j] & p_shift[j]
            p[j + shift] = p_[j] & p_shift[j]
            g[j + shift] = g[j + shift] ^^ g_[j]

    # cin = 1
    g = [1] + g[:]
    for i in range(length):
        g[i] = s_[i] ^^ g[i]
    return g

def kogge_ge(a, b):
    length = len(a)
    res = kogge_sub(a, b)
    return res[length] == 1

for i in range(2^10):
    # val1 = i
    # val2 = i
    val1 = rand()
    val2 = rand()

    # Addition
    res = val1 + val2
    res2 = kogge_add_2(to_bits(val1), to_bits(val2))
    res2_ = from_bits(res2)
    assert(res == res2_)
    res3 = kogge_add_2_v2(to_bits(val1), to_bits(val2))
    res3_ = from_bits(res3)
    assert(res == res3_)

    P_ = to_bits(P) + [0]
    (sub, ov) = kogge_sub_p(res2)

    if res >= P:
        assert(ov == 1)
        assert(from_bits(sub) == res - P)
    else:
        assert(ov == 0)

    # Subtraction
    res = (1 << P_LEN) + val1 - val2
    res2 = kogge_sub(to_bits(val1), to_bits(val2))
    res2_ = from_bits(res2)
    assert(res == res2_)

    # Comparison
    res = val1 >= val2
    res2 = kogge_ge(to_bits(val1), to_bits(val2))
    assert(res == res2)
