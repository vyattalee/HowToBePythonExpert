# -- coding: utf-8 --
# Python 2.7
data = {
    '': [],
    'aaaaa': ['a'],
    'aabb': ['ab'],
    'pww12k1ew': ['wke'],
    'brfgd12345ch12i': ['brfgdchi'],
    'abc1234567dabc2345db': ['abcd', 'bcad', 'cdab', 'dabc'],
}


def main(s):
    li = []
    left = 0
    right = 0
    max_length = 0
    for c in s:
        if c in s[left:right]:
            if right - left >= max_length:
                if right - left > max_length:
                    li = []
                    # python3 可用 li.clear()
                    max_length = right - left
                s[left:right] in li or li.append(s[left:right])
            left += s[left:right].index(c) + 1
        right += 1
    return li or [s]


if __name__ == '__main__':

    for s, r in data.items():
        print (main(s))