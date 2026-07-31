import os
import sys

def delete_json_files(folder_path):
    # 检查文件夹是否存在
    if not os.path.exists(folder_path):
        print(f"指定的文件夹路径 {folder_path} 不存在。")
        return
    # 检查路径是否为文件夹
    if not os.path.isdir(folder_path):
        print(f"{folder_path} 不是一个有效的文件夹路径。")
        return

    # 遍历文件夹中的所有文件和子文件夹
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            # 检查文件扩展名是否为 .json
            if file.lower().endswith('.json'):
                file_path = os.path.join(root, file)
                try:
                    # 删除文件
                    os.remove(file_path)
                    print(f"已删除文件: {file_path}")
                except Exception as e:
                    print(f"删除文件 {file_path} 时出错: {e}")

if __name__ == "__main__":
    # 检查命令行参数是否包含文件夹路径
    if len(sys.argv) != 2:
        print("用法: python script.py <文件夹路径>")
        sys.exit(1)

    # 获取命令行输入的文件夹路径
    folder_path = sys.argv[1]
    # 调用删除 JSON 文件的函数
    delete_json_files(folder_path)