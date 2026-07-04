import requests
import os

url = "https://sing-box-subscribe-doraemon.vercel.app/config/https://raw.githubusercontent.com/yaney01/chromego_merge/refs/heads/main/sub/base64.txt"
output_folder = "sub"
output_filename = "sing-box.json"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
}

try:
    response = requests.get(url, headers=headers, timeout=30)
except requests.RequestException as e:
    print(f"HTTP请求异常: {e}")
    raise SystemExit(1)

if response.status_code == 200:
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    output_path = os.path.join(output_folder, output_filename)
    with open(output_path, "w", encoding="utf-8") as file:
        file.write(response.text)
    print(f"成功将内容写入 {output_path}")
else:
    print(f"HTTP请求失败，状态码: {response.status_code}")
