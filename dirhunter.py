#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DirHunter - 目录/敏感路径扫描工具（纯 Python 标准库，零依赖）
适用于渗透测试资产梳理、CTF 目录爆破场景。

用法:
  交互模式:  python dirhunter.py            （什么都不带，进入菜单）
  命令行模式: python dirhunter.py -u http://target -t 32 -e php,html,txt

Python 3.7+ 即可，无需 pip install 任何东西。
"""

import argparse
import concurrent.futures
import datetime
import os
import ssl
import sys
import time
import urllib.request
import urllib.error

__version__ = "1.0.0"

# ---------------- Windows 控制台 ANSI 颜色支持 ----------------
try:
    import ctypes

    class _Color:
        def __init__(self):
            self.enabled = self._probe()

        def _probe(self):
            try:
                k = ctypes.windll.kernel32
                k.SetConsoleMode(k.GetStdHandle(-11), 7)
                return True
            except Exception:
                return sys.stdout.isatty()

        def wrap(self, code, s):
            return "\033[%sm%s\033[0m" % (code, s) if self.enabled else s

        def green(self, s):    return self.wrap("32", s)
        def yellow(self, s):   return self.wrap("33", s)
        def red(self, s):      return self.wrap("91", s)
        def cyan(self, s):     return self.wrap("36", s)
        def gray(self, s):     return self.wrap("90", s)
        def bold(self, s):     return self.wrap("1", s)
except Exception:
    class _Color:
        def green(self, s):    return s
        def yellow(self, s):   return s
        def red(self, s):      return s
        def cyan(self, s):     return s
        def gray(self, s):     return s
        def bold(self, s):     return s

C = _Color()

DEFAULT_EXTS = "php,html,txt,jsp,asp,zip,sql,bak,old,json,xml,yml,conf,log"
HERE = os.path.dirname(os.path.abspath(__file__))
BUILTIN_WL = os.path.join(HERE, "wordlists", "common.txt")
RESULTS_DIR = os.path.join(HERE, "results")

# 不跟随重定向，保留 301/302 信息
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

SSL_CTX = ssl._create_unverified_context()


def load_wordlist(path):
    """读字典，自动去空行去注释去重"""
    words, seen = [], set()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            w = line.strip()
            if w and not w.startswith("#") and w not in seen:
                seen.add(w)
                words.append(w)
    return words


def build_candidates(words, exts):
    """字典词 + 词.后缀 组合"""
    cands = list(words)
    for w in words:
        if w.endswith("/"):
            continue
        for e in exts:
            cands.append("%s.%s" % (w, e))
    return cands


def probe(url, timeout=8):
    """请求单个 URL，返回 (status, length) 或 (None, err)"""
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DirHunter/" + __version__,
            "Accept": "*/*",
            "Connection": "close",
        },
    )
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=SSL_CTX))
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(1024 * 512)  # 最多读 512KB，够判长度
            return resp.status, len(body)
    except urllib.error.HTTPError as e:
        return e.code, 0
    except Exception as e:
        return None, str(e)


def status_color(code):
    if code == 200:
        return C.green
    if code in (301, 302):
        return C.yellow
    if code == 403:
        return C.red
    if code >= 500:
        return C.cyan
    return C.gray


def scan(target, words, exts, threads, exclude, timeout, out_file):
    candidates = build_candidates(words, exts)
    if not target.endswith("/"):
        target += "/"

    print(C.bold("\n[*] 目标: %s" % target))
    print("[*] 字典: %d 词 x %d 后缀 = %d 条路径, 线程 %d" % (len(words), len(exts), len(candidates), threads))
    print("[*] 开始扫描... (Ctrl+C 随时中断)\n" + "-" * 62)

    found = []
    errors = [0]
    done = [0]
    total = len(candidates)
    t0 = time.time()
    lock_print = []  # 进度行控制

    def worker(path):
        url = target + path
        code, extra = probe(url, timeout)
        done[0] += 1
        if done[0] % 500 == 0:
            sys.stdout.write("\r    进度: %d/%d (%.0f%%)" % (done[0], total, done[0] * 100.0 / total))
            sys.stdout.flush()
        if code is None:
            errors[0] += 1
            return
        if code in exclude:
            return
        length = extra if isinstance(extra, int) else 0
        print("\r" + status_color(code)("[%d]" % code) + "  %-8s %8d  /%s" % ("", length, path))
        found.append((code, "/" + path, length))

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            list(ex.map(worker, candidates))
    except KeyboardInterrupt:
        print(C.red("\n\n[!] 用户中断，输出已收到的结果"))

    print("\r" + " " * 40 + "\r" + "-" * 62)
    cost = time.time() - t0
    print("[*] 完成: %d 条, 耗时 %.1fs, 发现 %d 个有效路径, 网络错误 %d" % (total, cost, len(found), errors[0]))
    print(C.bold("    200=存在  301/302=跳转  403=禁止访问(更可疑)  500=可尝试注入\n"))

    if found and out_file:
        os.makedirs(os.path.dirname(out_file), exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("# DirHunter %s  目标: %s  时间: %s\n" % (__version__, target, datetime.datetime.now()))
            f.write("# 格式: 状态码  长度  路径\n")
            for code, path, length in sorted(found, key=lambda x: (x[0], x[1])):
                f.write("%d\t%s\t%s\n" % (code, length, path))
        print("[*] 报告已保存: %s" % out_file)


def ask(prompt, default=None):
    tip = prompt + (" [回车=%s]" % default if default else "") + ": "
    v = input(tip).strip()
    return v if v else (default or "")


def interactive():
    while True:
        print("=" * 52)
        print(C.bold("  DirHunter v%s  目录扫描（交互模式）" % __version__))
        print("=" * 52)
        target = ask("请输入目标地址 (IP / 域名 / URL)", "127.0.0.1:8000")
        if "://" not in target:
            target = "http://" + target

        exts_s = ask("文件后缀 (逗号分隔)", DEFAULT_EXTS)
        exts = [e.strip().lstrip(".").lower() for e in exts_s.split(",") if e.strip()]

        threads_s = ask("线程数 1-128 (远程目标建议<=16)", "32")
        threads = int(threads_s) if threads_s.isdigit() and 1 <= int(threads_s) <= 128 else 32

        wl = ask("字典路径 (回车=内置 common.txt)", BUILTIN_WL)
        if not os.path.isfile(wl):
            print(C.yellow("[!] 字典不存在，改用内置字典"))
            wl = BUILTIN_WL
        words = load_wordlist(wl)

        exc_s = ask("排除的状态码 (404 之外还想排除的，如 302,400)", "")
        exclude = {404}
        for s in exc_s.split(","):
            s = s.strip()
            if s.isdigit():
                exclude.add(int(s))

        print("\n  目标 : %s\n  后缀 : %s\n  线程 : %d\n  字典 : %s (%d 词)" % (target, ",".join(exts), threads, wl, len(words)))
        c = ask("确认开始扫描？(Y=开始 N=重填 Q=退出)", "Y").lower()
        if c == "q":
            return
        if c != "y":
            continue

        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        host = target.split("://", 1)[1].replace(":", "_").replace("/", "_")
        out_file = os.path.join(RESULTS_DIR, "%s_%s.txt" % (host, stamp))
        try:
            scan(target, words, exts, threads, exclude, 8, out_file)
        except KeyboardInterrupt:
            print(C.red("\n[!] 已中断"))
        if ask("\n再扫一个目标？(Y=继续)", "N").lower() != "y":
            return


def main():
    p = argparse.ArgumentParser(
        prog="DirHunter",
        description="目录/敏感路径扫描工具（纯标准库，零依赖）",
        epilog="示例: python dirhunter.py -u http://192.168.1.100 -t 16 -e php,txt",
    )
    p.add_argument("-u", "--url", help="目标 URL（不给则进入交互模式）")
    p.add_argument("-w", "--wordlist", default=BUILTIN_WL, help="字典文件路径 (默认内置 common.txt)")
    p.add_argument("-e", "--extensions", default=DEFAULT_EXTS, help="逗号分隔的文件后缀")
    p.add_argument("-t", "--threads", type=int, default=32, help="线程数 (默认 32)")
    p.add_argument("--timeout", type=int, default=8, help="单请求超时秒数 (默认 8)")
    p.add_argument("-x", "--exclude", default="404", help="排除的状态码，逗号分隔 (默认 404)")
    p.add_argument("-o", "--output", help="报告输出文件 (默认自动存 results/)")
    p.add_argument("-v", "--version", action="version", version="DirHunter " + __version__)
    args = p.parse_args()

    if not args.url:
        interactive()
        return

    if not os.path.isfile(args.wordlist):
        sys.exit("[!] 字典不存在: %s" % args.wordlist)
    words = load_wordlist(args.wordlist)
    exts = [e.strip().lstrip(".").lower() for e in args.extensions.split(",") if e.strip()]
    exclude = set(int(s) for s in args.exclude.split(",") if s.strip().isdigit())
    target = args.url if "://" in args.url else "http://" + args.url

    if args.output:
        out_file = args.output
    else:
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        host = target.split("://", 1)[1].replace(":", "_").replace("/", "_")
        out_file = os.path.join(RESULTS_DIR, "%s_%s.txt" % (host, stamp))

    scan(target, words, exts, args.threads, exclude, args.timeout, out_file)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(1)
