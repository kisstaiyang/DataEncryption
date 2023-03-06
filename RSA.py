# Author：taiyang
# welcome to https://taiyang.space

import random
import math

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：确定素数
param：num
return：flag：如果是返回True；不是返回False
'''


def isPrime(num):
    if (num < 2):
        return False
    else:
        i = 2
        flag = True
        while i < num:
            # 如果num能被i整除，说明num不是质数
            if num % i == 0:
                # 只要num不是质数，将flag的值修改为 False
                flag = False
            i += 1
        return flag


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：大质数生成
param：num
return：num：随机生成的一个大质数
'''


def randPrime(n):
    rangeStart = 10 ** (n - 1)  # 10**4
    rangeEnd = (10 ** n) - 1  # 10**5-1
    while True:
        num = random.randint(rangeStart, rangeEnd)  # 返回rangestart到rangeend任意一个数
        if isPrime(num):  # 判断是否是质数，如果是则生成
            return num


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：寻找与f互质整数e，生成公钥中 e
param：num
return：num：公钥中的e
'''


# 寻找与f互质整数e
def findE(b):
    rangeStart = 2
    rangeEnd = b - 1
    while True:
        num = random.randint(rangeStart, rangeEnd)
        if euclid(num, b) == 1:  # 利用欧几里算法，如果值等于1，那么这个两个数互质
            return num


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：欧几里得算法
param：
return：
'''


def euclid(a, b):
    if a > b:
        x = a
        y = b
    else:
        x = b
        y = a
    while True:
        if y == 0:
            return x
        else:
            r = x % y
            x = y
            y = r


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：扩展欧几里得算法，求逆元
param：
return：
'''


def extendEculid(a, n):
    x1, x2, x3 = 1, 0, n
    y1, y2, y3 = 0, 1, a
    while y3 != 1 and y3 != 0 and y3 > 0:
        Q = math.floor(x3 / y3)
        t1, t2, t3 = x1 - Q * y1, x2 - Q * y2, x3 - Q * y3
        x1, x2, x3 = y1, y2, y3
        y1, y2, y3 = t1, t2, t3
    if y3 == 0:
        return 0
    if y3 == 1:
        if y2 > 0:
            return y2
        else:
            return n + y2


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：D、E和N的密钥生成
param：
return：key：密钥字典；结构：{'d': 8565578239, 'e': 7845277951, 'n': 9303319957}
'''


def getKey(size=5):
    p, q = randPrime(size), randPrime(size)  # 生成一对不相等且足够大的质数
    N = p * q  # 计算p、q的乘积
    f = (p - 1) * (q - 1)  # 计算n的欧拉函数
    e = findE(f)  # 选出一个与f互质的整数e
    d = extendEculid(e, f)  # 计算出e对于f的模反元素d  de mod f =1
    keys = {'d': d, 'e': e, 'n': N}  # 得出公钥与私钥
    return keys


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：从数字幂快速搜索模块
param：
return：
'''


def searchMoudle(x, n, mod):  # x**n mod mod
    if n == 0:
        return 1
    elif n % 2 == 0:
        p = searchMoudle(x, n / 2, mod)
        return (p * p) % mod
    else:
        return (x * searchMoudle(x, n - 1, mod)) % mod


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：生成hash值
param：M：明文
return：cc：哈希值
'''


def getHashCode(M, size=5):
    aa = hash(M)  # 得到哈希值
    cc = aa % 10 ** (size * 2 - 2)  # 将哈希值转化为整型
    return cc


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：加密
param：M：明文；密钥
return：s：加密后的密文
'''


def rsaEncode(M, d, N):
    s = searchMoudle(M, d, N)  # 使用私钥签名 hashM**d mod N 得到签名内容
    return s


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：解密
param：s：密文；密钥
return：w：解密后的明文
'''


def rsaDecode(s, e, n):
    w = searchMoudle(s, e, n)
    return w


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''


def main():
    key = getKey()

    # 公钥
    publicKey = [key["n"], key["e"]]
    print("生成的公钥为：{}".format(publicKey))
    # 私钥
    privateKey = [key["n"], key["d"]]
    print("生成的私钥为：{}".format(privateKey))

    plainText = input("请输入要加密的信息：")
    summaryBefore = getHashCode(plainText.encode("utf-8"))
    print("加密前的明文摘要为：", summaryBefore)

    cipherText = rsaEncode(summaryBefore, publicKey[1], publicKey[0])

    inputD = int(input("请输入密钥中的D："))
    summaryAfter = rsaDecode(cipherText, inputD, publicKey[0])
    print("\n解密后的明文摘要为：", summaryAfter)

    # 判断是否一致
    if summaryAfter == summaryBefore:
        print("\n明文摘要一致")
    else:
        print("\n摘要不一致，密钥错误")


if __name__ == '__main__':
    main()
