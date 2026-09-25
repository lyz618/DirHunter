# DirHunter 🔍

> 目录 / 敏感路径扫描工具

适用于渗透测试资产梳理、CTF 目录爆破场景。不依赖 requests、不依赖 dirsearch，`python dirhunter.py` 

## ✨ 特性

- **零依赖**：Python 3.7+ 标准库实现（urllib + 多线程），无需安装任何包
- **交互模式**：不带参数运行，按提示输入目标/后缀/线程即可，适合新手
- **命令行模式**：支持 `-u` `-w` `-e` `-t` 等参数，适合脚本调用
- **自动字典组合**：内置 300+ 常见敏感路径字典，自动再组合 php/html/txt/zip 等后缀
- **状态码智能提示**：200 存在 / 403 禁止访问（更可疑）/ 500 可尝试注入
- **不跟随重定向**：保留 301/302 信息
- **结果自动保存**：报告写入 `results/目标_时间戳.txt`
- **跨平台**：Windows / Linux / macOS / Kali 均可运行
- **彩色输出**：Windows 10 自动启用 ANSI 颜色，老系统自动降级为纯文本

## 🚀 快速开始

### Windows
双击 `run.bat` 即可（自动寻找本机 Python 3，找不到会给出下载地址）。

### Linux / Kali
```bash
git clone https://github.com/lyz618/DirHunter.git
cd DirHunter
python3 dirhunter.py
```

### 命令行用法
```bash
# 交互模式（不带参数）
python3 dirhunter.py

# 命令行模式
python3 dirhunter.py -u http://192.168.1.100 -t 16 -e php,txt,zip

# 指定自定义字典 + 输出文件
python3 dirhunter.py -u http://target -w mydict.txt -o result.txt

# 排除更多状态码、设置超时
python3 dirhunter.py -u http://target -x 404,400,302 --timeout 5
```

## 📖 参数说明

| 参数 | 说明 | 默认 |
|------|------|------|
| `-u` | 目标 URL（不给则进入交互模式） | - |
| `-w` | 字典路径 | 内置 `wordlists/common.txt` |
| `-e` | 文件后缀（逗号分隔） | `php,html,txt,jsp,asp,zip,sql,bak,old,json,xml,yml,conf,log` |
| `-t` | 线程数 | 32（远程目标建议 ≤16，避免触发 WAF） |
| `-x` | 排除的状态码 | 404 |
| `--timeout` | 单请求超时秒数 | 8 |
| `-o` | 报告输出文件 | `results/自动命名.txt` |

## 📊 状态码解读

| 状态码 | 含义 | 建议 |
|--------|------|------|
| 200 | 路径存在 | 重点关注：后台、备份、配置 |
| 301/302 | 跳转 | 通常说明目录存在 |
| 403 | 存在但禁止访问 | **更可疑**，尝试绕过（改 UA / 后缀 / 路径变换） |
| 500 | 服务端错误 | 可尝试注入测试 |

## 📁 项目结构

```
DirHunter/
├── dirhunter.py        # 主程序（单文件，标准库）
├── run.bat             # Windows 启动器
├── run.sh              # Linux/macOS 启动器
├── wordlists/
│   └── common.txt      # 内置字典（300+ 敏感路径）
├── results/            # 扫描报告输出目录（自动生成）
├── README.md
└── LICENSE
```

## ⚠️ 免责声明

本工具仅用于**授权的安全测试与教学场景**（如 CTF 竞赛、自有资产梳理）。未经授权对他人系统进行扫描属于违法行为，使用者需自行承担法律责任。

## 📝 License

MIT
