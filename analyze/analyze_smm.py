import openai
import os
import sys
import concurrent.futures
import re
import json

# 从环境变量中获取 API 密钥
api_key = os.environ.get("OPENAI_API_KEY", "")
if not api_key:
    print("请设置 OPENAI_API_KEY 环境变量。")
    sys.exit(1)

# 初始化 OpenAI 客户端
client = openai.OpenAI(
    api_key=api_key,
    base_url = os.environ.get("OPENAI_BASE_URL", "http://localhost:8000/v1/"),
    timeout=3600,
    max_retries=3
)

def extract_json_from_text(text):
    """从文本中提取JSON格式的内容"""
    if not text:
        return None
    
    # 定义JSON块的正则表达式模式
    json_pattern = re.compile(r'```json(.*?)```', re.DOTALL)
    
    # 查找第一个JSON块
    match = json_pattern.search(text)
    if match:
        json_str = match.group(1).strip()
        try:
            # 解析JSON
            json_obj = json.loads(json_str)
            return json.dumps(json_obj, ensure_ascii=False, indent=4)
        except json.JSONDecodeError:
            print("找到JSON块但解析失败")
    
    # 如果没有找到JSON块，尝试直接解析文本是否为JSON
    try:
        json_obj = json.loads(text)
        return json.dumps(json_obj, ensure_ascii=False, indent=4)
    except json.JSONDecodeError:
        print("未找到有效的JSON内容")
    
    return None

def analyze_c_code(file_path, prompt, call_relations, code_folder):
    try:
        with open(file_path, 'r') as file:
            c_code = file.read()

        function_name = os.path.splitext(os.path.basename(file_path))[0]
        callee_context = get_callee_code(function_name, call_relations, code_folder)

        if callee_context:
            full_prompt = f"{prompt}\n函数调用的其他函数代码:\n{callee_context}\n\n原函数代码:\n```c\n{c_code}\n```"
        else:
            full_prompt = f"{prompt}\n\n```c\n{c_code}\n```"

        analysis_result = ""
        response = client.chat.completions.create(
            model="deepseek-r1:32b",
            messages=[
                {"role": "user", "content": full_prompt},
                {"role": "assistant", "content": ""}
            ],
            temperature=0.6,
            top_p=0.95,
            timeout=3000
        )
        
        # 获取原始响应内容
        thinkchain = response.choices[0].message.reasoning_content
        json_content = response.choices[0].message.content
        
        # 当json_content为空时，尝试从thinkchain中提取
        if not json_content and thinkchain:
            print(f"JSON内容为空，尝试从thinkchain中提取: {file_path}")
            json_content = extract_json_from_text(thinkchain)
        
        return function_name, c_code, thinkchain, json_content
    except Exception as e:
        print(f"An error occurred while analyzing {file_path}: {e}")
        return None, None, None, None



def save_results(file_path, thinkchain, json_content, base_folder):
    relative_path = os.path.relpath(os.path.dirname(file_path), base_folder)
    output_folder = os.path.join("output", relative_path)

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


def parse_function_batches(file_path):
    batches = []
    try:
        with open(file_path, 'r', encoding='gbk') as f:
            for line in f:
                if "第" in line and "批函数:" in line:
                    functions = line.split(":")[1].strip().split(", ")
                    batches.append(functions)
    except Exception as e:
        print(f"Error reading function batches file: {e}")
    return batches


def find_function_files(functions, code_folder):
    function_files = []
    for func in functions:
        file_name = f"{func}.c"
        file_path = os.path.join(code_folder, file_name)
        if os.path.exists(file_path):
            function_files.append(file_path)
    return function_files


def parse_function_call_relations(file_path, code_folder):
    call_relations = {}
    try:
        with open(file_path, 'r', encoding='gbk') as f:
            for line in f:
                if "->" in line:
                    caller, callee = line.strip().split(" -> ")
                    if caller not in call_relations:
                        call_relations[caller] = {
                            "callees": [],
                            "file_path": os.path.join(code_folder, f"{caller}.c")
                        }
                    call_relations[caller]["callees"].append(callee)
    except Exception as e:
        print(f"Error reading function call relations file: {e}")
    return call_relations


def get_callee_code(caller, call_relations, code_folder):
    callee_code = ""
    if caller in call_relations:
        for callee in call_relations[caller]["callees"]:
            callee_file_path = os.path.join(code_folder, f"{callee}.c")
            if os.path.exists(callee_file_path):
                try:
                    with open(callee_file_path, 'r') as callee_file:
                        callee_code += f"\n\n```c\n{callee_file.read()}\n```"
                except Exception as e:
                    print(f"读取 {callee_file_path} 时出错: {e}")
    return callee_code



def process_subfolder(subfolder, prompt, base_folder, inner_max_workers):
    call_relations = parse_function_call_relations(os.path.join(subfolder, "function_call_relations.txt"), subfolder)
    batches = parse_function_batches(os.path.join(subfolder, "function_batches.txt"))
    all_results = []

    for batch in batches:
        function_files = find_function_files(batch, subfolder)
        if not function_files:
            continue

        with concurrent.futures.ThreadPoolExecutor(max_workers=inner_max_workers) as executor:
            future_to_file = {executor.submit(analyze_c_code, file_path, prompt, call_relations, subfolder): file_path for file_path in function_files}
            for future in concurrent.futures.as_completed(future_to_file):
                file_path = future_to_file[future]
                function_name = os.path.splitext(os.path.basename(file_path))[0]

                if function_name in call_relations:
                    called_functions = call_relations[function_name]["callees"]
                    print(f"函数 {function_name} 调用的函数及分析状态:")
                    for called_func in called_functions:
                        analyzed = any(entry["function_name"] == called_func for entry in all_results)
                        status = "已分析" if analyzed else "未分析"
                        print(f"{called_func}: {status}")
                else:
                    print(f"函数 {function_name} 没有调用其他函数。")

                try:
                    function_name, function_content, thinkchain, json_content = future.result()
                    if thinkchain or json_content:
                        print(f"File: {file_path}")
                        print(f"Analysis Result:")
                        print(thinkchain)
                        print(json_content)
                        print("-" * 80)

                        save_results(file_path, thinkchain, json_content, base_folder)

                        result_entry = {
                            "function_name": function_name,
                            "function_content": function_content,
                            "thinkchain_result": thinkchain,
                            "json_result": json_content
                        }
                        all_results.append(result_entry)
                except Exception as exc:
                    print(f'{file_path} generated an exception: {exc}')

    relative_path = os.path.relpath(subfolder, base_folder)
    output_folder = os.path.join("output", relative_path)
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    if all_results:
        save_combined_results(all_results, output_folder)


def save_combined_results(results, output_folder):
    combined_file_path = os.path.join(output_folder, "combined_results.json")
    with open(combined_file_path, 'w', encoding='utf-8') as combined_file:
        json.dump(results, combined_file, ensure_ascii=False, indent=4)


def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <code_folder_path> <prompt_txt_file_path>")
        sys.exit(1)

    code_folder_path = sys.argv[1]
    prompt_txt_file_path = sys.argv[2]

    try:
        with open(prompt_txt_file_path, 'r', encoding='utf-8') as prompt_file:
            prompt = prompt_file.read().strip()
    except Exception as e:
        print(f"Error reading prompt txt file: {e}")
        sys.exit(1)

    subfolders = []
    for root, dirs, files in os.walk(code_folder_path):
        if "function_batches.txt" in files and "function_call_relations.txt" in files:
            subfolders.append(root)

    outer_max_workers = 8
    inner_max_workers = 16

    with concurrent.futures.ThreadPoolExecutor(max_workers=outer_max_workers) as executor:
        futures = [executor.submit(process_subfolder, subfolder, prompt, code_folder_path, inner_max_workers) for subfolder in subfolders]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                print(f"子文件夹处理出错: {exc}")


if __name__ == "__main__":
    main()
