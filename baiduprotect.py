from idautils import *
from idaapi import *
from idc import *

import subprocess

#去除混淆
print("start")
#循环执行每一个段的内容
for segea in Segments():
    for funcea in Functions(segea, get_segm_end(segea)):#循环每个函数
        for (startea, endea) in Chunks(funcea):#从函数的开始到结束的地址
            for line in Heads(startea, endea):#遍历每一行汇编
                #如果汇编字符串的内容匹配如下数组内的内容
                if idc.GetDisasm(line) in ["ADRP            X8, #dword_C0144@PAGE", \
                                           "ADRP            X8, #dword_C0140@PAGE", \
                                           "ADRP            X8, #dword_C013C@PAGE", \
                                           "ADRP            X8, #dword_C0138@PAGE", \
                                           "ADRP            X8, #dword_C0134@PAGE", \
                                           "ADRP            X8, #dword_C0130@PAGE", \
                                           "ADRP            X8, #dword_C012C@PAGE", \
                                           "ADRP            X8, #dword_C0128@PAGE", \
                                           "ADRP            X8, #dword_C0124@PAGE", \
                                           "ADRP            X8, #dword_C0120@PAGE", \
                                           "ADRP            X8, #dword_C011C@PAGE", \
                                           "ADRP            X8, #dword_C0118@PAGE"]:
                    # pi = subprocess.Popen(
                    #     ['F:\\keystone-0.9.2-win64\\kstool.exe', 'arm64', 'ADRP X8, 0xA0000', hex(line)], shell=True,
                    #     stdout=subprocess.PIPE)#开启这个kstool.exe 进行将 'ADRP X8, 0xA0000' 转成 机器码
                    print(line) 
                    # output = pi.stdout.read()#读取匹配到那一行的内容 这里是替换后的汇编的内容b'ADRP X8, 0xA0000 = [ c8 00 00 90 ]\r\n'
                    # print(output)
                    # asmcode = str(output[20:33])[:-1]  # c8 00 00 90  asmcode 的内容 
                   
                    # print(asmcode)
                    # asmcode = asmcode.split(" ")
                    # asmcode = "0x" + asmcode[4] + asmcode[3] + asmcode[2] + asmcode[1]





                    # print(asmcode)

                    asmcode ="0x900000C8"#这里的机器码 可以通过keystone_demo.py 进行计算
                    patch_dword(line, int(asmcode, 16))
                elif idc.GetDisasm(line) in ["ADRP            X9, #dword_C0140@PAGE", \
                                             "ADRP            X9, #dword_C013C@PAGE", \
                                             "ADRP            X9, #dword_C0138@PAGE", \
                                             "ADRP            X9, #dword_C0134@PAGE", \
                                             "ADRP            X9, #dword_C0130@PAGE", \
                                             "ADRP            X9, #dword_C012C@PAGE", \
                                             "ADRP            X9, #dword_C0128@PAGE", \
                                             "ADRP            X9, #dword_C0124@PAGE", \
                                             "ADRP            X9, #dword_C0120@PAGE", \
                                             "ADRP            X9, #dword_C011C@PAGE", \
                                             "ADRP            X9, #dword_C0118@PAGE"]:
                    # pi = subprocess.Popen(
                    #     ['D:\\keystone-0.9.2-win64\\kstool.exe', 'arm64', 'ADRP X9, 0xA0000', hex(line)], shell=True,
                    #     stdout=subprocess.PIPE)
                    print(line)
                    # output = pi.stdout.read()
                    # asmcode = str(output[20:33])[:-1]
                   
                    # print(asmcode)
                    # asmcode = asmcode.split(" ")
                    # asmcode = "0x" + asmcode[4] + asmcode[3] + asmcode[2] + asmcode[1]
                    # print(asmcode)
                    asmcode ="0x900000C9"#这里的机器码 可以通过keystone_demo.py 进行计算
                    patch_dword(line, int(asmcode, 16))
                elif idc.GetDisasm(line) in ["ADRP            X10, #dword_C0140@PAGE", \
                                             "ADRP            X10, #dword_C013C@PAGE", \
                                             "ADRP            X10, #dword_C0138@PAGE", \
                                             "ADRP            X10, #dword_C0134@PAGE", \
                                             "ADRP            X10, #dword_C0130@PAGE", \
                                             "ADRP            X10, #dword_C012C@PAGE", \
                                             "ADRP            X10, #dword_C0128@PAGE", \
                                             "ADRP            X10, #dword_C0124@PAGE", \
                                             "ADRP            X10, #dword_C0120@PAGE", \
                                             "ADRP            X10, #dword_C011C@PAGE", \
                                             "ADRP            X10, #dword_C0118@PAGE"]:
                    # pi = subprocess.Popen(
                    #     ['D:\\keystone-0.9.2-win64\\kstool.exe', 'arm64', 'ADRP X10, 0xA0000', hex(line)], shell=True,
                    #     stdout=subprocess.PIPE)
                    # output = pi.stdout.read()
                    # asmcode = str(output[20:33])[:-1]
                    # asmcode = asmcode.split(" ")
                    # asmcode = "0x" + asmcode[4] + asmcode[3] + asmcode[2] + asmcode[1]
                    # print(asmcode)
                    asmcode = "0x900000CA"  #这里的机器码 可以通过keystone_demo.py 进行计算
                    patch_dword(line, int(asmcode, 16))
