import frida
import sys

device = frida.get_usb_device(1)
session = device.attach("Test")

scr = """
var str_name_so = "libbaiduprotect.so";
var n_addr_so = Module.findBaseAddress(str_name_so);
// console.log("libbaiduprotect.so base address:");
// console.log(n_addr_so.toString(16));

//getencrpty_functable.py 得到的数据 写入到decode_func2str_list 中
var decode_func2str_list = [
"sub_25FD0***09598DD611D1543C",
"sub_2607C***8CA86FFB66BD1DAFC58A62B543A840AACA833ED67ABD44A28B8864F477F361B7D68D6BFD2B9058A2D2852AF671B255ECF79077F37EBB098FCE8573FB3FB053ADC3CB56EE62B55CA49FAD5FB346",
......
]

for (let i in decode_func2str_list)
{
    var str = decode_func2str_list[i].substring(12) //取要被解密的字符串
    var funcaddr = parseInt(decode_func2str_list[i].substring(4, 9), 16)//# 获取函数地址

    var n_funcaddr = funcaddr + parseInt(n_addr_so, 16); //so的动态基址+函数的基址
    //console.log("n_funcaddr address:");
    //console.log(n_funcaddr.toString(16));

    var call_func = new NativeFunction(ptr(n_funcaddr), 'pointer', ['pointer']);//new 一个函数
    var str_arg = Memory.allocUtf8String(str);//分配一个字符串大小的字符串指针
    var p_str_ret = call_func(str_arg);//调用解密函数
    var str_ret = Memory.readCString(p_str_ret);//获取解密的内容

    console.log("\\"" + str_ret + "\\"" + ",");
}
"""


def on_message(message, data):
    print(message)
    # print(message['payload'].encode("utf-8"))


script = session.create_script(scr)
script.on("message", on_message)
script.load()
