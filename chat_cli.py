#!/usr/bin/env python3
"""OpenAI 兼容接口的简单命令行聊天脚本。"""

import argparse
import os
import sys

from openai import OpenAI


def parse_args():
    parser = argparse.ArgumentParser(
        description="向 OpenAI 兼容 API 发送 chat completion 请求。"
    )
    parser.add_argument(
        "-m",
        "--message",
        default="hello",
        help="用户消息内容（默认: hello）",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("LLM_MODEL", "your-model-name"),
        help="模型名称（默认: LLM_MODEL 环境变量，或 your-model-name）",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("LLM_BASE_URL", "https://your-api.example.com/v1"),
        help="API base URL（默认: LLM_BASE_URL 环境变量，或 https://your-api.example.com/v1）",
    )
    parser.add_argument(
        "--api-key-env",
        default="MY_CUSTOM_API_KEY",
        help="读取 API Key 的环境变量名（默认: MY_CUSTOM_API_KEY）",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    api_key = os.environ.get(args.api_key_env)
    if not api_key:
        print(f"错误: 未找到环境变量 {args.api_key_env}", file=sys.stderr)
        sys.exit(1)

    client = OpenAI(api_key=api_key, base_url=args.base_url)
    resp = client.chat.completions.create(
        model=args.model,
        messages=[{"role": "user", "content": args.message}],
    )
    print(resp.choices[0].message.content)


if __name__ == "__main__":
    main()
