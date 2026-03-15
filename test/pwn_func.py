# 该文件集成分析二进制文件的一些函数
# 模型可以通过该文件调用一些函数来获取信息
import subprocess
import os
from pwn import *

RED = "\033[31m"
RESET = "\033[0m"

context.log_level = 'error'  # 关闭 pwntools 的日志输出


def llm_checksec(binary_path: str) -> str:
    # checksec获取保护，后续记住这些保护
    
    
# radare2获取函数列表
