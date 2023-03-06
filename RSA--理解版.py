# Author：taiyang
# welcome to https://taiyang.space

import random
import math

'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：判断输入的p、q是不是质数
param：p、q
return：如果是返回 True
'''


def judgePandQ(p, q):
    ls = []
    ls.append(p)
    ls.append(q)
    for x in range(0, 2):
        if int(ls[x]) > 1:
            # 查看因子
            for i in range(2, int(ls[x])):
                if (int(ls[x]) % i) == 0:
                    print(int(ls[x]), "不是质数")
                    print(i, "乘于", int(ls[x]) / i, "是", int(ls[x]))
                    return False
                else:
                    return True
        # 如果输入的数字小于或等于 1，不是质数
        else:
            print(int(ls[x]), "不是质数")


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：计算出 N 和 L
param：p、q
return：N、L
'''


def getNandL(p, q):
    N = p * q
    L = (p - 1) * (q - 1)
    return N, L


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：计算出 e
param：p、q
return：一个存放所有E的列表
'''


def getE(p, q):
    N, L = getNandL(p, q)
    listOfE = []
    for i in range(2, L):
        if math.gcd(i, L) == 1:
            listOfE.append(i)
    return listOfE


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：计算出 d
param：p、q
return：一个字典；结构{e1:d1, e2:d2}   每一个e都有对应的d并且去掉重复的
'''


def getdict_EandD(p, q):
    N, L = getNandL(p, q)
    listOfE = getE(p, q)
    dict_EandD = {}
    for e in listOfE:
        for d in range(2, L):
            # 构建字典并去重
            if (e * d) % L == 1 and e != d:
                dict_EandD[e] = d
    return dict_EandD


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：计算公钥和私钥
param：p、q
return：publicKey, privateKey, N, L，E，D
'''


def getKey(p, q):
    if judgePandQ(p, q):
        N, L = getNandL(p, q)
        listOfE = getE(p, q)
        dict_EandD = getdict_EandD(p, q)

        # 获取E的值
        print("这是所有可用的E\n", listOfE, "\n")
        E = int(input("请选择一个喜欢的值："))
        while (True):
            if E not in listOfE:
                print("你输入的E不在给出的列表中，请重新输入！\n")
                E = int(input("请选择一个喜欢的值："))
            else:
                break

        # 根据E的值在dict_EandD字典中找D的值
        D = dict_EandD.get(E)

        # 构建公钥、私钥
        # 公钥：（N，E）
        # 私钥：（N，D）
        publicKey = (N, E)
        privateKey = (N, D)
        return publicKey, privateKey, N, L, E, D
    else:
        print("输入的p，q不是质数！请重新输入")


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：自动获得p、q
param：null
return：p、q
'''


def autoGetPandQ():
    # 考虑到性能的原因，这里只生成10——100的素数
    primeList = []
    for i in range(10, 100):
        isPrime = True
        for j in range(2, i):
            if i % j == 0:
                isPrime = False
        if isPrime:
            primeList.append(i)

    p = random.choice(primeList)
    q = random.choice(primeList)

    # 防止出现一样的情况
    while (True):
        if p == q:
            p = random.choice(primeList)
            q = random.choice(primeList)
        else:
            break
    return p, q


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：打印p、q、N、L、publicKey、privateKey、E
param：p、q、N、L、publicKey、privateKey
return：null
'''


def printParam(publicKey, privateKey, N, L, E, D, p, q):
    print()
    print("p为：", p, " q为：", q)
    print("计算出的N为：", N)
    print("计算出的L为：", L)
    print("你选择的E为：", E)
    print("该E对应的D为：", D)
    print("计算出的公钥为：", publicKey)
    print("计算出的私钥为：", privateKey)


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：对明文进行加密
param：plainText，N，E
return：加密后的密文 cipherText
'''


def rsaEncode(plainText, N, E):
    cipherText = plainText % N
    for i in range(1, E):
        cipherText = (cipherText * (plainText % N)) % N
    return cipherText


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：对密文进行解密
param：cipherText，N，
return：null
'''


def rsaDecode(cipherText, N):
    plainText = cipherText % N
    D = int(input("请输入私钥中的D："))
    for i in range(1, D):
        plainText = (plainText * (cipherText % N)) % N
    return plainText


'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
description：RSA算法，进行加解密
param：p，q
return：null
'''


def rsaMain(p, q):
    publicKey, privateKey, N, L, E, D = getKey(p, q)
    printParam(publicKey, privateKey, N, L, E, D, p, q)
    plainText = int(input("\n加密\n请输入你要加密的明文："))
    cipherText = rsaEncode(plainText, N, E)
    print('你加密后的密文是：', cipherText)

    print("\n解密")
    plainText = rsaDecode(cipherText, N)
    print('你所解密的明文是：', plainText)


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''


def main():
    print("*************************************")
    print("*******        RSA算法        ********")
    print("*******  自动生成质数p、q：输入1 ********")
    print("*******  手动输入质数p、q：输入2 ********")
    print("*************************************")
    option = int(input("请输入你要选择的模式："))

    while (True):
        if option == 1:
            p, q = autoGetPandQ()
            rsaMain(p, q)
            break

        elif option == 2:
            p = int(input("请输入p："))
            q = int(input("请输入q："))
            rsaMain(p, q)
            break

        else:
            print("输入有误！请重新输入！")
            option = int(input("请输入你要选择的模式："))


if __name__ == '__main__':
    try:
        main()
    except ValueError:
        print("输入有误！")
