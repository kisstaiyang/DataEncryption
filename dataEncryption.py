# Author：taiyang
# welcome to https://taiyang.space

import RSA as rsa
from DES import DES

des = DES()

'''
假设现在有两个人要在互联网上传输信息，Alice、Bob
Alice 发送给 Bob
完整过程：
        Alice:
            1、A把信息原文进行哈希运算，得到信息的数字摘要

            2、A用自己私钥，采用非对称加密算法，对数字摘要进行加密，得到数字签名
            
            3、A用对称算法的密钥，采用对称算法，对信息原文和数字签名和A的公钥一起加密，得到加密信息
            
            4、A用B的公钥，采用非对称算法，把对称密钥加密，形成信封。就像是对称密钥装到了B公钥加密的信封里面
            
            5、A把加密信息和数字信封一起发给B
                
        Bob:
            1、B收到数字信息，用自己的私钥解密信封，拿到对称密钥

            2、B用对称密钥，把加密信息解密，得到信息原文和数字签名和A的公钥
            
            3、B用A的公钥解密数字签名，得到数字摘要1
            
            4、B将原文用同样的哈希算法，得到数字摘要2
            
            5、将摘要1和摘要2对比。如果相等，则原文没有被修改，签名是真实的

由于RSA、DES算法纯手撕出来的，暂时还不能实现完整过程
但是大概过程还是能实现的

本文实现的过程：
            Alice：
                1、对明文进行对称加密，使用DES
                2、Alice用自己的私钥对使用DES加密后的加密信息进行RSA加密，得到数字签名
                3、Alice用Bob的公钥对第 2 步得到的数字签名进行RSA加密，获得最终的密文
                
            Bob：
                1、用自己的私钥对密文进行解密得到数字签名
                2、用Alice的公钥对数字签名进行解密，得到信息摘要
                3、比对加解密前后信息摘要
                

我们只验证明文的完整性，Alice的DES密钥双方已提前知晓
为社么不能获得加密前的明文呢？
    1. 我水平不够
    2. 图省事，直接用hash()获得摘要，hash不能逆向


DES加密中密钥为：taiyang，且使用普通模式，不用CBC模式
公钥是所有人都能知道，私钥是只有自己知道

'''

''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''


def Alice(message):
    # 第 1 步
    encryptedInformation = des.normalEncode(message)

    # 第 2 步
    '''''''''''''''''''傻逼代码'''''''''''''''''''''''''
    temp = encryptedInformation[:6]
    global dictionary
    dictionary = {temp: encryptedInformation}
    ''''''''''''''''''''''''''''''''''''''''''''''''''''''
    summaryBefore = int(temp, 16)  # 信息摘要
    digitalSignature = rsa.rsaEncode(summaryBefore, Alice_D, Alice_N)  # 数字签名

    # 第 3 步
    cipherText = rsa.rsaEncode(digitalSignature, Bob_E, Bob_N)

    return cipherText, digitalSignature


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''


def Bob(cipherText):
    # 第 1 步
    digitalSignature = rsa.rsaDecode(cipherText, Bob_D, Bob_N)

    # 第 2 步
    summaryAfter = rsa.rsaDecode(digitalSignature, Alice_E, Alice_N)

    # 第 3 步
    encryptedInformation = dictionary[str(hex(summaryAfter))]

    # 第 4 步
    plainText = des.normalDecode(encryptedInformation)
    return digitalSignature, plainText


''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''''


def main():
    print("{:*^60}".format("简单模拟数据加密过程"))
    message = input("请输入要加密的信息：")
    # 加密
    cipherText, summaryBefore = Alice(message)

    # 解密
    summaryAfter, plainText = Bob(cipherText)

    # 打印
    if message == plainText:
        print("\n明文摘要一致")
        print("\nAlice生成的信息照要为：", summaryBefore)
        print("\nAlice生成的最终加密密文为：", cipherText, "\n")
        print("{:*^50}".format("解密"))
        print("\nBob获得信息摘要为：", summaryAfter)
        print("\nBob解出的信息原文为：", plainText)
    else:
        print("\nBob解出的信息原文为：", plainText)
        print("\nDES的密钥输入错误！")


if __name__ == '__main__':
    AliceKey = rsa.getKey()
    AlicePublicKey = [AliceKey["n"], AliceKey["e"]]
    AlicePrivateKey = [AliceKey["n"], AliceKey["d"]]
    Alice_N = AlicePublicKey[0]
    Alice_E = AlicePublicKey[1]
    Alice_D = AlicePrivateKey[1]

    BobKey = rsa.getKey()
    BobPublicKey = [BobKey["n"], BobKey["e"]]
    BobPrivateKey = [BobKey["n"], BobKey["d"]]
    Bob_N = AlicePublicKey[0]
    Bob_E = AlicePublicKey[1]
    Bob_D = AlicePrivateKey[1]

    main()
