import os
import shutil

# 源文件夹路径
source_folder = 'output'
# 目标文件夹路径
target_folder = 'output_adjust'

# 确保目标文件夹存在
if not os.path.exists(target_folder):
    os.makedirs(target_folder)

# 遍历源文件夹中的所有文件
for root, dirs, files in os.walk(source_folder):
    for file in files:
        # 检查文件是否为C代码文件
        if file.endswith('.c'):
            # 提取子文件夹名称和新的文件名
            parts = file.split('_')
            if len(parts) >= 3:
                sub_folder_name = parts[1]
                new_file_name = '_'.join(parts[2:]).replace('.c_opt.c', '.c')

                # 构建目标子文件夹路径
                target_sub_folder = os.path.join(target_folder, sub_folder_name)

                # 确保目标子文件夹存在
                if not os.path.exists(target_sub_folder):
                    os.makedirs(target_sub_folder)

                # 构建源文件路径和目标文件路径
                source_file_path = os.path.join(root, file)
                target_file_path = os.path.join(target_sub_folder, new_file_name)

                # 移动并重命名文件
                shutil.move(source_file_path, target_file_path)
                print(f"Moved {source_file_path} to {target_file_path}")