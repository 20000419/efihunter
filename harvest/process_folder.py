import os
import subprocess
import sys

def process_files_in_folder(folder_path):
    # 定义需要处理的文件类型
    file_extensions = ['.efi', '.bin', '.img']

    # 遍历文件夹中的所有文件及其子文件夹
    for root, _, files in os.walk(folder_path):
        for file in files:
            # 检查文件扩展名是否符合要求
            if any(file.endswith(ext) for ext in file_extensions):
                file_path = os.path.join(root, file)
                print(f"Processing file: {file_path}")
                
                # 调用 extract-ida.py 处理当前文件
                try:
                    subprocess.run(['python', 'extract-ida.py', file_path], check=True)
                except subprocess.CalledProcessError as e:
                    print(f"Error processing file {file_path}: {e}")

    print("Done processing all files.")

# 主函数：从命令行获取文件夹路径
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python process_folder.py <path_to_directory>")
        sys.exit(1)
    
    folder_path = sys.argv[1]
    
    if not os.path.isdir(folder_path):
        print(f"Invalid directory path: {folder_path}")
        sys.exit(1)

    # 处理文件夹中的所有文件
    process_files_in_folder(folder_path)

