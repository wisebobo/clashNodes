import requests
import yaml
import json
import subprocess
import time
import glob
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import urllib3

# 禁用 InsecureRequestWarning 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# 用于测试下载速度的大文件 URL，可根据实际情况替换
TEST_FILE_URL = "https://nbg1-speed.hetzner.com/100MB.bin"
# TEST_FILE_URL = "https://freetestdata.com/wp-content/uploads/2022/02/Free_Test_Data_10MB_MP4.mp4"
# 下载速度阈值，单位为 KB/s
DOWNLOAD_SPEED_THRESHOLD = 500
# 下载超时时间，单位为秒
DOWNLOAD_TIMEOUT = 30

def test_download_speed(node, proxies):
    try:
        start_time = time.time()
        response = requests.get(TEST_FILE_URL, proxies=proxies, stream=True, verify=False)
        if response.status_code == 200:
            total_size = 0
            for chunk in response.iter_content(chunk_size=1024):
                if time.time() - start_time > DOWNLOAD_TIMEOUT:
                    print(f"{node['name']} download timed out after {DOWNLOAD_TIMEOUT} seconds.")
                    return None
                if chunk:
                    total_size += len(chunk)
            end_time = time.time()
            download_time = end_time - start_time
            download_speed = total_size / download_time / 1024  # 转换为 KB/s

            if download_speed > DOWNLOAD_SPEED_THRESHOLD:
                print(f"Valid node: {node['name']}, Download Speed: {download_speed:.2f} KB/s")
                node['download_speed'] = download_speed
                result = node
            else:
                print(f"Node {node['name']} download speed {download_speed:.2f} KB/s is below threshold.")
                result = None
        else:
            # print(f"Invalid node: {node['name']} (Status code: {response.status_code})")
            result = None
    except Exception as e:
        # print(f"{node['name']} - Error testing proxy {node['server']}:{node['port']}: {e}")
        result = None

    return result

def test_node(node, proxies, process=None):
    response = requests.get("https://www.google.com", proxies=proxies, timeout=5, verify=False)
    if process:
        process.terminate()
        process.wait()

    if response.status_code == 200:
        # return test_download_speed(node, proxies)
        return node
    else:
        print(f"Invalid node: {node['name']} (Status code: {response.status_code})")
        return None

# 测试 Shadowsocks 代理
def test_ss(node):
    try:
        # Start a local shadowsocks client
        command = [
            'ss-local', '-s', str(node['server']), '-p', str(node['port']), '-m', str(node['cipher']), '-k', str(node['password']), '-l', '1080', '--fast-open'
        ]
        subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # 测试代理
        proxies = {
            "http": "socks5h://127.0.0.1:1080",
            "https": "socks5h://127.0.0.1:1080"
        }
        
        result = test_node(node, proxies)
    except Exception as e:
        # print(f"{node['name']} - Error testing Shadowsocks proxy {node['server']}:{node['port']}: {e}")
        result = None
    finally:
        # Kill any running ss-local process
        subprocess.run(['pkill', '-f', 'ss-local'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result

# 测试 Trojan 代理
def test_trojan(node):
    try:
        proxies = {
            "http": f"http://{node['password']}@{node['server']}:{node['port']}",
            "https": f"http://{node['password']}@{node['server']}:{node['port']}"
        }
        response = requests.get("https://www.google.com", proxies=proxies, timeout=10, verify=not node.get("skip-cert-verify", False))
        return test_node(node, proxies)
    except Exception as e:
        # print(f"{node['name']} - Error testing Trojan proxy {node['server']}:{node['port']}: {e}")
        return None

# 测试 Vmess 代理
def test_vmess(node):
    try:
        # 使用 Xray 或 V2Ray 测试 Vmess 代理
        # 这里假设你已经安装了 Xray 或 V2Ray，并且可以通过命令行调用
        # 以下是一个示例命令（需要根据实际情况调整）
        command = [
            "xray-bin/xray", "run", "-config", "vmess_config.json"
        ]
        # 生成 Vmess 配置文件
        vmess_config = {
            "inbounds": [
                {
                    "port": 1080,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": node.get("udp", False)  # 支持 UDP
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": node["server"],
                                "port": node["port"],
                                "users": [
                                    {
                                        "id": node["uuid"],
                                        "alterId": node.get("alterId", 0),
                                        "security": node.get("cipher", "auto")
                                    }
                                ]
                            }
                        ]
                    },
                    "streamSettings": {
                        "network": node.get("network", "tcp"),
                        "security": "tls" if node.get("tls", False) else "none",
                        "tlsSettings": {
                            "serverName": node.get("ws-opts", {}).get("headers", {}).get("host", ""),
                            "allowInsecure": node.get("skip-cert-verify", False)
                        },
                        "wsSettings": {
                            "path": node.get("ws-opts", {}).get("path", ""),
                            "headers": node.get("ws-opts", {}).get("headers", {})
                        }
                    }
                }
            ]
        }
        with open("vmess_config.json", "w") as f:
            json.dump(vmess_config, f)

        # 启动 Xray
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(2)  # 等待 Xray 启动

        # 测试代理
        proxies = {
            "http": "socks5://127.0.0.1:1080",
            "https": "socks5://127.0.0.1:1080"
        }
        
        return test_node(node, proxies, process)
    except Exception as e:
        # print(f"{node['name']} - Error testing Vmess proxy {node['server']}:{node['port']}: {e}")
        return None

# 下载 nodes.yaml 文件
def download_nodes_yaml(url):
    response = requests.get(url)
    if response.status_code == 200:
        with open("nodes.yaml", "wb") as file:
            file.write(response.content)
        print("Downloaded nodes.yaml successfully.")
    else:
        print(f"Failed to download nodes.yaml. Status code: {response.status_code}")
        exit(1)

# 读取节点文件
def read_nodes_yaml(*file_patterns):
    all_data = []
    unique_nodes = set()
    for pattern in file_patterns:
        # 根据文件通配符模式获取所有匹配的文件路径
        file_paths = glob.glob(pattern)
        for file_path in file_paths:
            try:
                with open(file_path, "r", encoding="utf-8") as file:
                    data = yaml.safe_load(file)
                    if data and "proxies" in data:
                        for node in data["proxies"]:
                            if not isinstance(node.get("port"), int):
                                continue
                            # 选择能唯一标识节点的关键信息
                            node_key = (
                                node.get("type"),
                                node.get("server"),
                                node.get("port"),
                                node.get("cipher"),
                                node.get("password"),
                                node.get("uuid")
                            )
                            if node_key not in unique_nodes:
                                unique_nodes.add(node_key)
                                all_data.append(node)
            except Exception as e:
                print(f"Error reading {file_path}: {e}")

    return {"proxies": all_data}

# 主函数
def main():
    # 读取节点文件
    data = read_nodes_yaml("nodes_*.yaml")

    # 提取代理列表
    proxies = data.get("proxies", [])

    # 使用线程池测试代理
    valid_nodes = []
    with ThreadPoolExecutor(max_workers=50) as executor:  # 限制为 50 个线程
        futures = []
        for node in proxies:
            if node["type"] == "ss":
                futures.append(executor.submit(test_ss, node))
            elif node["type"] == "trojan":
                futures.append(executor.submit(test_trojan, node))
            elif node["type"] == "vmess":
                futures.append(executor.submit(test_vmess, node))

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                valid_nodes.append(result)

    # 创建规则
    rules = {"proxies": valid_nodes}

    # 写入规则文件
    with open("rules.yaml", "w") as file:
        yaml.safe_dump(rules, file)

    print(f"Rules generated and saved to rules.yaml. Valid nodes: {len(valid_nodes)}")

if __name__ == "__main__":
    main()
