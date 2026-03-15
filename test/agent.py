#!/usr/bin/env python3
"""Use r2pipe to disassemble a local binary and send assembly to Ollama via LangChain."""
import argparse
import os
import subprocess
import sys

try:
    import r2pipe
except ImportError:
    print("r2pipe is not installed. Please run: pip install r2pipe")
    sys.exit(1)

try:
    from langchain_community.chat_models import ChatOllama
    from langchain_core.messages import HumanMessage
except ImportError:
    print("langchain or langchain-community is not installed. Please run: pip install langchain langchain-community")
    sys.exit(1)


def extract_function_asm(binary_path: str, func_name: str ) -> str:
    """使用 r2pipe 提取目标 ELF 文件中指定函数的汇编代码"""
    if not os.path.exists(binary_path):
        raise FileNotFoundError(f"二进制文件不存在: {binary_path}")

    print(f"[*] 正在使用 Radare2 分析：{binary_path} ...")
    cmd = ["r2" , "-q" , "-c" , "aaa" , "-c" , f"pdf @ {func_name}" , binary_path]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        asm_code = result.stdout
        if not asm_code.strip():
            raise ValueError(f"未能提取到函数 {func_name} 的汇编代码。请确认函数名是否正确，或尝试其他函数。")
        return asm_code
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Radare2 执行失败: {e.stderr.strip()}") from e

def call_ollama_analysis(assembly: str, model: str, base_url: str) -> str:
    prompt = f"""
        你是一个顶级的网络安全专家和 PWN 选手。
        下面是我通过 Radare2 从一个 ELF 文件中提取出的汇编代码。

        请你分析这段汇编：
        1. 它大致在做什么？
        2. 是否存在安全漏洞（比如缓冲区溢出）？如果存在，请指出是哪条指令或函数调用引起的。

        汇编代码如下：
        {assembly}
    """
    
    llm = ChatOllama(model=model, base_url=base_url, temperature=0.1)
    messages = [HumanMessage(content=prompt)]
    response = llm.invoke(messages)
    return response.content


def main() -> int:
    parser = argparse.ArgumentParser(description="Use r2pipe + Ollama to analyze binary assembly.")
    parser.add_argument("--ip", default="http://172.20.80.1:11434", help="Ollama base URL (默认已指定)")
    parser.add_argument("--model", default="qwen2.5-coder:7b", help="Ollama 模型名 (默认已指定)")
    parser.add_argument("--binary", help="要分析的 ELF 二进制文件路径 (默认已指定)")
    parser.add_argument("--func", default="main", help="要提取汇编的函数名，比如 sym.main")
    parser.add_argument("--lines", type=int, default=300, help="最大发送给模型的汇编行数")
    args = parser.parse_args()

    func_to_analyze = args.func
    if not func_to_analyze.startswith("sym.") and func_to_analyze != "main":
        # r2 中默认函数名前缀可加 sym.
        func_to_analyze = f"sym.{func_to_analyze}"

    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary_path = os.path.join(script_dir, args.binary)
    asm = extract_function_asm(binary_path, func_to_analyze)

    print("=== [assembly excerpt] ===")
    print(asm)
    print("=== [end assembly] ===\n")

    analysis = call_ollama_analysis(asm, model=args.model, base_url=args.ip)
    print("=== [Ollama analysis] ===")
    print(analysis)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
