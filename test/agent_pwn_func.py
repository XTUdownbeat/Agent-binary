import argparse
import os
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langchain_classic.agents import AgentExecutor, create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate
from langchain_classic.agents import AgentExecutor, create_structured_chat_agent


RED = "\033[31m"
RESET = "\033[0m"

from pwn_func import llm_checksec, enumerate_functions, decompile_function, find_useful_strings, llm_ROPgadget , check_seccomp

# 转换
checksec_security_tools = tool(llm_checksec)
enumerate_functions_tool = tool(enumerate_functions)
decompile_function_tool = tool(decompile_function)
find_useful_strings_tool = tool(find_useful_strings)
ropgadget_tool = tool(llm_ROPgadget)
check_seccomp_tool = tool(check_seccomp)

tools = [
    checksec_security_tools,
    enumerate_functions_tool,
    decompile_function_tool,
    find_useful_strings_tool,
    ropgadget_tool,
    check_seccomp_tool
]

def main():
    parser = argparse.ArgumentParser(description="自动化二进制漏洞分析 Agent")
    parser.add_argument("--file", type=str, default="overflow", help="要分析的二进制文件路径")
    parser.add_argument("--ip", default="http://172.26.96.1:11434", help="Ollama 服务地址")
    parser.add_argument("--model", default="qwen2.5-coder:14b", help="Ollama 模型名称")
    args = parser.parse_args()

    # 获取二进制文件位置

    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary_path = os.path.join(script_dir, args.file)
    if not os.path.exists(binary_path):
        print(f"{RED}二进制文件不存在: {binary_path}{RESET}")
        return
    
    print(f"{RED}[*] 正在唤醒大模型并加载工具 ~~~~ {RESET}")
    
    # 初始化本地模型
    llm = ChatOllama(
        model=args.model, 
        base_url=args.ip, 
        temperature=0.1
    )

    # 编写prompt,引导模型调用工具
    prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一个顶级的自动化漏洞挖掘与利用 Agent。你必须使用提供的工具来获取信息。
            
            你能使用的工具如下（必须严格使用这些确切的工具名字）：
            {tool_names}
            
            # 关于工具的详细说明：
            # {tools}
            
            [重要规则 - 严禁违背]
            1. 绝不允许连续两次调用同一个工具获取相同的信息！如果你已经拿到了函数列表，下一步必须是反汇编关键函数（如 main 或 backdoor），或者直接输出结论。
            2. 你的目标是写出漏洞分析和利用思路，不要在无意义的信息收集中浪费时间。
             
            为了使用工具，你必须严格输出如下格式的 Markdown JSON 代码块（千万不要输出多余的解释和废话）：
            ```json
            {{
                "action": "工具名字",
                "action_input": {{
                    "参数名1": "参数值1"
                }}
            }}
            ```
             
            【重要安全利用规则】
            1. 如果你在函数列表中看到了诸如 set_secommp、prctl 或 sandbox 相关的函数，你必须调用 check_seccomp 工具。
            2. 如果发现 seccomp 禁用了 execve 系统调用，绝对不允许使用 system('/bin/sh') 这种利用方式！你必须明确提出构造 ORW (Open, Read, Write) ROP 链来读取 flag。
                    
            当你通过一系列工具调用，收集完所有信息并得出最终漏洞利用策略时，使用以下格式输出最终报告：
            ```json
            {{
                "action": "Final Answer",
                "action_input": "你的最终漏洞分析报告与完整 Pwn 利用思路(用中文回答),如果可以的话尝试给出exp"
            }}
            ```
            """),
            ("human", "目标任务：{input}\n\n请严格遵守 JSON 代码块输出格式，开始你的分析！\n\n{agent_scratchpad}")
        ])

    # 创建agent逻辑
    agent = create_structured_chat_agent(llm, tools, prompt)

    # 实例化AgentExecutor
    # 这个类会负责管理整个对话流程，包括调用工具、接收结果、更新对话历史等
    agent_executor = AgentExecutor(
        agent=agent, 
        tools=tools, 
        verbose=True, # 打开详细日志，观察工具调用和模型思考过程
        max_iterations=10,  # 限制最大迭代次数，防止死循环
        handle_parsing_errors=True
    )

    print("\n" + "="*50)
    print(f"{RED}[*] 开始分析二进制文件: {binary_path} ~~~~ {RESET}")
    print("="*50 + "\n")

    try:
        response = agent_executor.invoke({
            "input": f"目标文件路径是：{binary_path}。请开始你的漏洞分析工作，找出潜在的漏洞并告诉我你的利用策略。"
        })

        print("\n" + "="*50)
        print("🤖 Agent 最终输出报告:")
        print("="*50)
        print(response["output"])

    except Exception as e:
         print(f"[-] Agent 运行过程中出现异常: {e}")

if __name__ == "__main__":
    main()