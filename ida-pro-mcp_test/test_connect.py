import requests
import json

# 配置
IDA_URL = "http://172.26.96.1:13337/mcp"
OLLAMA_URL = "http://172.26.96.1:11434/api/generate"

def ida_mcp_call(tool_name, arguments):
    """
    针对标准的 MCP-over-JSONRPC 实现
    顶级方法固定为 tools/call
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",  # 这里的 method 固定为 tools/call
        "params": {
            "name": tool_name,    # 工具名放在这里
            "arguments": arguments # 参数放在这里
        }
    }

    try:
        r = requests.post(IDA_URL, json=payload, timeout=15)
        r.raise_for_status()
        data = r.json()

        if "error" in data:
            # 如果 tools/call 还是不行，尝试不带 tools/ 前缀的 call
            if data["error"].get("code") == -32601:
                payload["method"] = "call"
                r = requests.post(IDA_URL, json=payload, timeout=15)
                data = r.json()
            
            if "error" in data:
                print(f"[-] 错误: {data['error']}")
                return None

        # 解析 MCP 返回的标准格式
        # result: { content: [ { type: 'text', text: '...' } ] }
        result = data.get("result", {})
        if "content" in result:
            return result["content"][0].get("text", "")
        
        return str(result)
        
    except Exception as e:
        print(f"[-] 请求异常: {e}")
        return None

def main():
    target = "main"
    print(f"[*] 正在通过 MCP 协议请求反编译: {target}")

    # 调用 decompile 工具
    code = ida_mcp_call("decompile", {"addr": target})

    if not code or "error" in code.lower():
        print("[-] 获取伪代码失败。")
        print(f"[*] 调试返回内容: {code}")
        return

    print("\n" + "="*20 + " IDA Pseudocode " + "="*20)
    print(code)
    print("="*56 + "\n")

    # Ollama 分析
    print("[*] 正在发送至 Ollama (qwen2.5-coder:7b) 分析...\n")
    prompt = f"你是一个逆向专家，分析这段伪代码逻辑：\n{code}"
    
    try:
        r = requests.post(OLLAMA_URL, json={
            "model": "qwen2.5-coder:7b",
            "prompt": prompt,
            "stream": False
        })
        print("="*20 + " LLM Analysis " + "="*20)
        print(r.json().get("response"))
    except Exception as e:
        print(f"[-] Ollama 分析失败: {e}")

if __name__ == "__main__":
    main()