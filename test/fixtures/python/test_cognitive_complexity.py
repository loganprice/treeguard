# ruleid: py-cognitive-complexity
def deeply_nested_complex_function(a, b, c):
    if a > 0:
        for i in range(10):
            if b > 5:
                while c < 100:
                    if a == b:
                        try:
                            c += 1
                        except Exception:
                            c = 0
                    else:
                        c += 2
            else:
                for j in range(5):
                    if c > 0:
                        c -= 1
    return c

# ok: py-cognitive-complexity
def simple_linear_function(x, y):
    if x > 0:
        return x + y
    return y
