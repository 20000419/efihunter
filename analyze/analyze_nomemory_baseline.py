import openai
import os
import sys
import concurrent.futures
import re

# 初始化 OpenAI 客户端
client = openai.OpenAI(
    api_key = os.environ.get("OPENAI_API_KEY", ""),
    base_url = os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1/")
)


def analyze_c_code(file_path, prompt):
    try:
        # 读取 C 代码文件
        with open(file_path, 'r') as file:
            c_code = file.read()

        # 构建完整的提示
        full_prompt = f"{prompt}\n\n```c\n{c_code}\n```"

        # 调用本地大模型进行分析
        response = client.chat.completions.create(
            model="deepseek-r1:32b",
            messages=[
                {"role": "user", "content": full_prompt},
                {"role": "assistant", "content": ""}
            ]
        )

        # 提取模型的回复
        analysis_result = response.choices[0].message.content

        return file_path, analysis_result

    except Exception as e:
        print(f"An error occurred while analyzing {file_path}: {e}")
        return file_path, None


def extract_thinkchain_and_json(result):
    thinkchain_pattern = r"<think>(.*?)</think>"
    json_pattern = r"```json(.*?)```"

    thinkchain_match = re.search(thinkchain_pattern, result, re.DOTALL)
    json_match = re.search(json_pattern, result, re.DOTALL)

    thinkchain = thinkchain_match.group(1).strip() if thinkchain_match else ""
    json_content = json_match.group(1).strip() if json_match else ""

    return thinkchain, json_content


def save_results(file_path, thinkchain, json_content, base_folder):
    # 获取原文件相对于输入文件夹的相对路径
    relative_path = os.path.relpath(os.path.dirname(file_path), base_folder)
    output_folder = os.path.join("output", relative_path)

    # 创建 thinkchain 和 json 子文件夹
    thinkchain_folder = os.path.join(output_folder, "thinkchain")
    json_folder = os.path.join(output_folder, "json")

    for folder in [thinkchain_folder, json_folder]:
        if not os.path.exists(folder):
            os.makedirs(folder)

    file_name = os.path.splitext(os.path.basename(file_path))[0]
    thinkchain_file_path = os.path.join(thinkchain_folder, f"{file_name}_thinkchain.txt")
    json_file_path = os.path.join(json_folder, f"{file_name}_output.json")

    with open(thinkchain_file_path, 'w', encoding='utf-8') as thinkchain_file:
        thinkchain_file.write(thinkchain)

    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        json_file.write(json_content)


def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <code_folder_path> <prompt_txt_file_path>")
        sys.exit(1)

    code_folder_path = sys.argv[1]
    prompt_txt_file_path = sys.argv[2]

    # 读取 txt 文件中的 prompt 信息
    try:
        with open(prompt_txt_file_path, 'r', encoding='utf-8') as prompt_file:
            prompt = prompt_file.read().strip()
    except Exception as e:
        print(f"Error reading prompt txt file: {e}")
        sys.exit(1)

    # 遍历文件夹中的所有 .c 文件
    for root, _, files in os.walk(code_folder_path):
        c_files = [os.path.join(root, file) for file in files if file.endswith('.c')]
        if not c_files:
            continue

        # 使用线程池并发处理代码文件
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            future_to_file = {executor.submit(analyze_c_code, file_path, prompt): file_path for file_path in c_files}
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    file_path, result = future.result()
                    if result:
                        thinkchain, json_content = extract_thinkchain_and_json(result)

                        # 输出分析结果到命令行界面（不包含 prompt）
                        print(f"File: {file_path}")
                        print(f"Analysis Result:")
                        print(thinkchain)
                        print(json_content)
                        print("-" * 80)

                        # 保存结果到文件
                        save_results(file_path, thinkchain, json_content, code_folder_path)
                except Exception as exc:
                    print(f'{file_path} generated an exception: {exc}')


if __name__ == "__main__":
    main()