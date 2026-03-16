import requests

def test():
    # 注意这里的方法名带了 tools/ 前缀
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/decompile", 
        "params": {"addr": "main"}
    }
    r = requests.post("http://172.26.96.1:13337/mcp", json=payload)
    print(r.text)

test()