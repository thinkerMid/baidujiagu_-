'''
# X86

keystone_test(KS_ARCH_X86, KS_MODE_16, b"add eax, ecx")

keystone_test(KS_ARCH_X86, KS_MODE_32, b"add eax, ecx")

keystone_test(KS_ARCH_X86, KS_MODE_64, b"add rax, rcx")

keystone_test(

KS_ARCH_X86, KS_MODE_32, b"add %ecx, %eax", KS_OPT_SYNTAX_ATT)

keystone_test(

KS_ARCH_X86, KS_MODE_64, b"add %rcx, %rax", KS_OPT_SYNTAX_ATT)

# ARM

keystone_test(KS_ARCH_ARM, KS_MODE_ARM, b"sub r1, r2, r5")

keystone_test(

KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN, b"sub r1, r2, r5")

keystone_test(KS_ARCH_ARM, KS_MODE_THUMB, b"movs r4, #0xf0")

keystone_test(

KS_ARCH_ARM, KS_MODE_THUMB + KS_MODE_BIG_ENDIAN, b"movs r4, #0xf0")

# ARM64

keystone_test(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, b"ldr w1, [sp, #0x8]")

# Hexagon

keystone_test(

KS_ARCH_HEXAGON, KS_MODE_BIG_ENDIAN, b"v23.w=vavg(v11.w,v2.w):rnd")

# Mips

keystone_test(KS_ARCH_MIPS, KS_MODE_MIPS32, b"and $9, $6, $7")

keystone_test(

KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN, b"and $9, $6, $7")

keystone_test(KS_ARCH_MIPS, KS_MODE_MIPS64, b"and $9, $6, $7")

keystone_test(

KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN, b"and $9, $6, $7")

# PowerPC

keystone_test(

KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN, b"add 1, 2, 3")

keystone_test(KS_ARCH_PPC, KS_MODE_PPC64, b"add 1, 2, 3")

keystone_test(

KS_ARCH_PPC, KS_MODE_PPC64 + KS_MODE_BIG_ENDIAN, b"add 1, 2, 3")

# Sparc

keystone_test(

KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_LITTLE_ENDIAN, b"add %g1, %g2, %g3")

keystone_test(

KS_ARCH_SPARC, KS_MODE_SPARC32 + KS_MODE_BIG_ENDIAN, b"add %g1, %g2, %g3")

# SystemZ

keystone_test(KS_ARCH_SYSTEMZ, KS_MODE_BIG_ENDIAN, b"a %r0, 4095(%r15,%r1)")
————————————————

参考：https://blog.csdn.net/weixin_39633276/article/details/111746324


'''




from keystone import *
from capstone import *
from capstone.arm64 import *

'''


'''



code = "adrp	x8, #0xA0000"

try:
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    encode,count = ks.asm(code,0x6F90) #这里的0x88030 是text段的首地址 IDA上 ctrl +s 可以看到
    print(bytes(encode))
    print(count)
except KsError as e:
    print("Error: %s"%e)

#输出
# b'\x08\x05\x00\x90'
# 1


Data = b'\xC8\x00\x00\x90'

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
#allInsn_arm64 = md.disasm(Data, 0x0000);
for i in md.disasm(Data, 0x6F90):
    print("%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))

#输出
#1000:	adrp	x8, #0xa1000


