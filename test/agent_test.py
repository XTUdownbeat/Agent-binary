import subprocess
import sys
import os

RED = "\033[31m"
RESET = "\033[0m"

from langchain_community.chat_models import ChatOllama
from langchain_core.messages import HumanMessage
import r2pipe

# 先radare2分析二进制，获取汇编代码

def get_asm_code(binary_path: str,func_name: str) -> str:
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"二进制文件不存在: {binary_path}")
    
    print(f"{RED}[*] 正在使用 Radare2 分析：{binary_path} ...{RESET}")
    # 启动一个新的进程去运行radare2命令，获取函数的汇编代码
    # 后续可以多写一些命令来获取更多信息，比如函数调用图、字符串引用等
    cmd = [
        "r2",
        "-q",
        "-c",
        "aaa",
        "-c",
        "afl",
        "-c",
        f"pdf @ {func_name}",
        "-c",
        "q",
        binary_path,
    ]
    try:
        result = subprocess.run(cmd , capture_output=True , text=True , check=True)
        asm_code = result.stdout
        if not asm_code.strip():
            raise ValueError(f"未能提取到函数 {func_name} 的汇编代码。请确认函数名是否正确，或尝试其他函数。")
        return asm_code
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Radare2 执行失败: {e.stderr.strip()}") from e
    
# 将汇编代码发送给 Ollama 模型进行分析
def call_ollama_analysis(assembly: str, model: str, base_url: str) -> str:
    prompt = f"""
        你是一个顶级的网络安全专家和 PWN 选手。
        下面是我通过 Radare2 从一个 ELF 文件中提取出的汇编代码。

        请你分析这段汇编：
        1. 它大致在做什么？
        2. 是否存在安全漏洞（比如缓冲区溢出,整数溢出，数组下标溢出）？如果存在，请指出是哪条指令或函数调用引起的。

        汇编代码如下：
        {assembly}
    """

    llm = ChatOllama(model=model , base_url = base_url , temperature=0.1)
    messages = [HumanMessage(content=prompt)]
    response = llm.invoke(messages)
    return response.content

# 结合以上函数，构建一个完整的流程：从命令行参数获取二进制文件路径和函数名，提取汇编代码，调用 Ollama 分析，并输出结果
def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Use r2pipe + Ollama to analyze binary assembly.")
    parser.add_argument("--ip", default="http://172.20.80.1:11434", help="Ollama base URL (默认已指定)")
    parser.add_argument("--model", default="qwen2.5-coder:7b", help="Ollama 模型名 (默认已指定)")
    parser.add_argument("--file" , default="pwn" , help="要分析的ELF文件")
    parser.add_argument("--func" , default="main" , help="要提取汇编的函数名，比如 sym.main")

    args = parser.parse_args()
    function_to_analysis = args.func
    # if not function_to_analysis.startswith("sym."):
    #      function_to_analysis = f"sym.{function_to_analysis}"
    
    # vscode连接wsl，写文件绝对路径
    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary_path = os.path.join(script_dir, args.file)

    # 调用radare2获得汇编代码
    asm_code = get_asm_code(binary_path , function_to_analysis)

    #给ollama分析
    analysis_result = call_ollama_analysis(asm_code , args.model , args.ip)
    print(f"\n{RED}=== [analysis result] ==={RESET}")
    print(analysis_result)
    print(f"\n{RED}=== [end analysis] ==={RESET}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")