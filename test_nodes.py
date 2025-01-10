import requests
import yaml
import json
import subprocess
import time

# Xray 配置文件模板
XRAY_CONFIG_TEMPLATE = {
    "inbounds": [
        {
            "port": 1080,  # 本地监听端口
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": True
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "",  # 动态填充协议
            "settings": {},  # 动态填充设置
            "streamSettings": {}  # 动态填充传输设置
        }
    ]
}

# 测试 Shadowsocks 代理
def test_ss(server, port, password, cipher):
    try:
        proxies = {
            "http": f"socks5://{cipher}:{password}@{server}:{port}",
            "https": f"socks5://{cipher}:{password}@{server}:{port}"
        }
        response = requests.get("https://www.google.com", proxies=proxies, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"Error testing Shadowsocks proxy {server}:{port}: {e}")
        return False

# 测试 Trojan 代理
def test_trojan(server, port, password, sni, skip_cert_verify):
    try:
        proxies = {
            "http": f"http://{password}@{server}:{port}",
            "https": f"http://{password}@{server}:{port}"
        }
        response = requests.get("https://www.google.com", proxies=proxies, timeout=10, verify=not skip_cert_verify)
        return response.status_code == 200
    except Exception as e:
        print(f"Error testing Trojan proxy {server}:{port}: {e}")
        return False

# 测试 Vmess 代理
def test_vmess(server, port, uuid, alter_id, cipher, network, ws_opts, tls, skip_cert_verify):
    try:
        # 生成 Xray 配置文件
        config = XRAY_CONFIG_TEMPLATE.copy()
        config["outbounds"][0]["protocol"] = "vmess"
        config["outbounds"][0]["settings"] = {
            "vnext": [
                {
                    "address": server,
                    "port": port,
                    "users": [
                        {
                            "id": uuid,
                            "alterId": alter_id,
                            "security": cipher
                        }
                    ]
                }
            ]
        }
        config["outbounds"][0]["streamSettings"] = {
            "network": network,
            "security": "tls" if tls else "none",
            "tlsSettings": {
                "serverName": ws_opts.get("headers", {}).get("host", ""),
                "allowInsecure": skip_cert_verify
            },
            "wsSettings": {
                "path": ws_opts.get("path", ""),
                "headers": ws_opts.get("headers", {})
            }
        }

        # 将配置文件写入临时文件
        config_path = "xray_config.json"
        with open(config_path, "w") as f:
            json.dump(config, f)

        # 启动 Xray
        xray_process = subprocess.Popen(["./xray-bin/xray", "-config", config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # 等待 Xray 启动
        time.sleep(2)

        # 测试代理
        proxies = {
            "http": "socks5://127.0.0.1:1080",
            "https": "socks5://127.0.0.1:1080"
        }
        response = requests.get("https://www.google.com", proxies=proxies, timeout=10)

        # 停止 Xray
        xray_process.terminate()
        xray_process.wait()

        # 检查响应
        return response.status_code == 200
    except Exception as e:
        print(f"Error testing Vmess proxy {server}:{port}: {e}")
        return False

# 读取节点文件
with open("nodes.yaml", "r") as file:
    nodes = yaml.safe_load(file)

# 测试节点并生成规则
valid_nodes = []
for node in nodes:
    if node["type"] == "ss":
        if test_ss(node["server"], node["port"], node["password"], node["cipher"]):
            valid_nodes.append(node)
            print(f"Valid node: {node['name']}")
        else:
            print(f"Invalid node: {node['name']}")
    elif node["type"] == "trojan":
        if test_trojan(node["server"], node["port"], node["password"], node.get("sni", ""), node.get("skip-cert-verify", False)):
            valid_nodes.append(node)
            print(f"Valid node: {node['name']}")
        else:
            print(f"Invalid node: {node['name']}")
    elif node["type"] == "vmess":
        if test_vmess(
            node["server"], node["port"], node["uuid"], node.get("alterId", 0), node.get("cipher", "auto"),
            node.get("network", "tcp"), node.get("ws-opts", {}), node.get("tls", False), node.get("skip-cert-verify", False)
        ):
            valid_nodes.append(node)
            print(f"Valid node: {node['name']}")
        else:
            print(f"Invalid node: {node['name']}")

# 创建规则
rules = []
for node in valid_nodes:
    rule = {
        "name": node["name"],
        "type": "load_balance" if "load_balance" in node["name"] else "test",
        "server": node["server"],
        "port": node["port"],
        "protocol": node["type"]
    }
    if node["type"] == "ss":
        rule["cipher"] = node["cipher"]
        rule["password"] = node["password"]
    elif node["type"] == "trojan":
        rule["password"] = node["password"]
        rule["sni"] = node.get("sni", "")
        rule["skip-cert-verify"] = node.get("skip-cert-verify", False)
    elif node["type"] == "vmess":
        rule["uuid"] = node["uuid"]
        rule["alterId"] = node.get("alterId", 0)
        rule["cipher"] = node.get("cipher", "auto")
        rule["network"] = node.get("network", "tcp")
        rule["ws-opts"] = node.get("ws-opts", {})
        rule["tls"] = node.get("tls", False)
        rule["skip-cert-verify"] = node.get("skip-cert-verify", False)
    rules.append(rule)

# 写入规则文件
with open("rules.yaml", "w") as file:
    yaml.safe_dump(rules, file)

print("Rules generated and saved to rules.yaml")
