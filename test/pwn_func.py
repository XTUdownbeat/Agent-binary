# 该文件集成分析二进制文件的一些函数
# 模型可以通过该文件调用一些函数来获取信息
import json
import subprocess
import os
from pwn import *

RED = "\033[31m"
RESET = "\033[0m"

context.log_level = 'error'  # 关闭 pwntools 的日志输出


def llm_checksec(binary_path: str) -> str:
    """
    检查二进制文件的安全机制
    当你拿到一个新的程序的时候，需要了解其是否开启了Canary, NX, PIE, RELRO等安全机制时调用该工具
    返回值将告诉你程序的防御效果，以决定后面的利用策略
    """

    try:
        if not os.path.isfile(binary_path):
            raise FileNotFoundError(f"{RED}Error: File '{binary_path}' not found.{RESET}")
        elf = ELF(binary_path)
        sec_info = {
            "Arch": elf.arch,
            "RELRO": elf.relro,
            "Stack Canary": elf.canary,
            "NX": elf.nx,
            "PIE": elf.pie,
        }

        # 格式化便于ai读入
        report = "[安全机制结果]"
        for key , value in sec_info.items():
            report += f"\n{key}: {value}"
        return report
    except Exception as e:
        return f"{RED}安全机制检测失败: {str(e)}{RESET}"

def enumerate_functions(binary_path: str) -> str:
    """
    枚举二进制文件的所有自定义函数以及地址。
    当你需要了解程序的大致结构，寻找入口点(main),和一些敏感函数(system,memcpy,strcmp等)或者漏洞函数(backdoor,/bin/sh调用等)时调用此工具
    (已自动过滤掉动态链接库的函数和一些无意义的函数，以节省上下文)
    """
    
    # 使用 aflj 获取 JSON 格式输出，方便过滤
    cmd = ["r2", "-q", "-c", "aaa", "-c", "aflj", binary_path]

    try:
        result = subprocess.run(cmd , capture_output=True, text=True, check=True)
        functions = json.loads(result.stdout)
        
        report = "[函数列表]"
        for func in functions:
            name = func.get("name", "")
            # 只分析自定义函数，过滤掉库函数
            if not name.startswith("sym.imp.") and not name.startswith("loc."):
                addr = hex(func.get("offset", 0))
                size = func.get("size", 0)
                report += f"- 函数名:{name} 地址:{addr} 大小:{size}bytes\n"
        return report if report != "[函数列表]" else "[+] 未找到明显的自定义函数"
    except subprocess.CalledProcessError as e:
        return f"{RED}函数枚举失败: {str(e)}{RESET}"
    
def decompile_function(binary_path: str, function_name: str) -> str:
    """
    获取指定函数的汇编代码
    必须在获取了函数列表，并且决定深入某个函数(如main函数)进行分析时调用此工具
    需要传入完整的函数名(如sys.main或 main)
    """
   
    target_func = function_name if function_name.startswith("sym.") else f"sym.{function_name}"
    if function_name == "main":
        target_func = "main"

    cmd = ["r2" , "-q" , "-c" , "aaa" , "-c" , f"pdf @{target_func}" , binary_path]
    try:
        result = subprocess.run(cmd , capture_output=True , text=True , check=True)
        if not result.stdout.strip():
            return f"{RED}[-] 未找到函数 {function_name} 的汇编代码，请确认函数名是否正确{RESET}"
        return f"[{function_name}函数的汇编代码]\n{result.stdout}"
    except subprocess.CalledProcessError as e:
        return f"{RED}函数反编译失败: {str(e)}{RESET}"
    
def find_useful_strings(binary_path: str) -> str:
    """
    查找二进制文件中有用的字符串
    当你需要寻找一些敏感字符串(如flag,secret,password,/bin/sh等)或者一些提示信息(如错误信息，日志等)时调用此工具
    这些字符串可能会给你提供一些利用的线索或者帮助你理解程序的功能
    """

    # 使用izj获取数据段字符串    
    cmd = ["r2", "-q", "-c", "aaa", "-c", "izj", binary_path]

    try:
        result = subprocess.run(cmd , capture_output=True , text=True , check=True)
        strings = json.loads(result.stdout)
        
        report = "[有用字符串列表]"
        for s in strings:
            content = s.get("string", "")
            # 过滤掉无意义的字符串，保留可能有用的
            if any(keyword in content.lower() for keyword in ["flag", "secret", "password", "passwd", "/bin/sh", "sh", "error", "log"]):
                report += f"- {content}\n"
        return report if report != "[有用字符串列表]" else "[+] 未找到明显有用的字符串"
    except subprocess.CalledProcessError as e:
        return f"{RED}字符串查找失败: {str(e)}{RESET}"
    
# ROPgadget寻找工具

def llm_ROPgadget(binary_path: str) -> str:
    """
    寻找二进制文件中的ROP gadget
    当你需要构造ROP链进行利用时，调用此工具寻找一些常用的gadget(如pop rdi; ret等)，以便后续构造利用链
    该工具会返回一些常见寄存器操作的gadget地址，帮助你快速找到利用所需的gadget
    """

    cmd = ["ROPgadget", "--binary", binary_path, "--only", "pop|ret"]

    try:
        result = subprocess.run(cmd , capture_output=True , text=True , check=True)
        gadgets = result.stdout.strip()
        return f"[ROP Gadget列表]\n{gadgets}" if gadgets else "[+] 未找到明显有用的ROP gadget"
    except subprocess.CalledProcessError as e:
        return f"{RED}ROP gadget 寻找失败: {str(e)}{RESET}" 

# 检测沙箱
def check_seccomp(binary_path: str, stdin_payload: str = "\n") -> str:
    """
    检查二进制文件是否开启了 seccomp 沙箱以及具体的过滤规则。
    如果程序存在 read/scanf/gets 等阻塞等待输入的逻辑，它可能会导致本工具超时。
    此时，你可以通过 `stdin_payload` 参数传入特定的字符串（比如 "\\n"、"1\\n" 或大量的 "A"），尝试让程序跑过输入阻塞点，触发沙箱加载机制。
    """
    cmd = ["seccomp-tools", "dump", binary_path]

    try:
        # 将大模型传进来的 payload (例如包含换行符的字符串) 转为字节流，通过 input 参数喂给子进程
        # 处理大模型可能传入的转义字符，如 "\\n" -> "\n"
        actual_payload = stdin_payload.encode('utf-8').decode('unicode_escape').encode('utf-8')
        
        result = subprocess.run(
            cmd, 
            input=actual_payload, 
            capture_output=True, 
            timeout=5
        )
        
        output = result.stdout.decode('utf-8', errors='ignore').strip()
        
        if output:
            return f"[Seccomp 规则详细解析]\n{output}"
        else:
            return "[-] 程序正常结束或崩溃，但未检测到 Seccomp 规则的加载。"
            
    except subprocess.TimeoutExpired:
        return (
            f"{RED}[-] seccomp-tools 执行超时。程序卡在了某个输入等待点。{RESET}\n"
            f"【系统提示】：你刚才尝试发送的 stdin_payload 是 '{stdin_payload}'，但它没能让程序执行到沙箱加载点（如 prctl 调用处）。\n"
            "请重新查看 `main` 函数的汇编逻辑，弄清楚程序到底需要什么样的输入才能跳出循环或分支，然后重新调用本工具并传入正确的 `stdin_payload`！"
        )
    except Exception as e:
        return f"{RED}Seccomp 检查失败: {str(e)}{RESET}"