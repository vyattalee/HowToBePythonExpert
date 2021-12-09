

try:
    a = 1000
    n = '0'
    n1 = 0
    x = a/n1
except ZeroDivisionError as e:
    print("zero divide:",e)
except Exception as e:
    print("default:", e)