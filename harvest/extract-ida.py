import sys
import os
from headless_ida import HeadlessIda

if len(sys.argv) < 2:
    print("Usage: python extract-ida.py <path_to_binary_file>")
    sys.exit(1)

binary_path = sys.argv[1]
file_name = os.path.basename(binary_path).split('.')[0]

if not os.path.isfile(binary_path):
    print(f"Invalid file path: {binary_path}")
    sys.exit(1)

headlessida = HeadlessIda("C:/Program Files/IDA Pro 7.7/idat64.exe", binary_path)

import idaapi
import idautils
import idc
import ida_loader
import networkx as nx
import json


# 创建一个函数图
def create_function_graph():
    graph = nx.DiGraph()
    # 遍历所有的函数
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        graph.add_node(func_name)
        # 遍历当前函数中的指令，查找调用其他函数的指令
        for head in idautils.Heads(func_ea, idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
            # 使用新的 API 获取指令助记符
            mnem = idc.print_insn_mnem(head)
            if mnem == "call":
                # 获取被调用的函数
                called_func_ea = idc.get_operand_value(head, 0)
                called_func_name = idc.get_func_name(called_func_ea)
                if called_func_name:
                    graph.add_edge(func_name, called_func_name)
    return graph


# 获取函数调用关系
def get_function_call_relations(graph):
    call_relations = []
    for source, target in graph.edges:
        call_relations.append(f"{source} -> {target}")
    return call_relations


# 获取反编译的 C 代码或反汇编代码并保存到指定文件夹
def decompile_function(func_start, output_folder):
    try:
        # 使用 IDA Pro 的反编译接口获取反编译结果
        func = idaapi.decompile(func_start)
        if func is not None:
            # 获取函数的名称
            func_name = idc.get_func_name(func_start)
            # 如果没有名字，使用地址作为函数名
            if not func_name:
                func_name = f"func_{func_start:08X}"
            # 创建保存路径
            output_path = os.path.join(output_folder, f"{func_name}.c")
            with open(output_path, 'w') as f:
                # 写入反编译的 C 代码
                f.write(str(func))
                print(f"Function '{func_name}' decompiled and saved to {output_path}")
    except Exception as e:
        # 捕获异常，打印错误信息，进行反汇编并保存
        print(f"Failed to decompile function at {hex(func_start)}: {e}")
        func_name = idc.get_func_name(func_start)
        if not func_name:
            func_name = f"func_{func_start:08X}"
        output_path = os.path.join(output_folder, f"{func_name}_disasm.txt")
        func_end = idc.get_func_attr(func_start, idc.FUNCATTR_END)
        with open(output_path, 'w') as f:
            for insn_ea in idautils.Heads(func_start, func_end):
                insn_text = idc.generate_disasm_line(insn_ea, 0)
                f.write(f"{hex(insn_ea)}: {insn_text}\n")
            print(f"Function '{func_name}' disassembled and saved to {output_path}")


# 按批次输出函数，处理循环
def get_functions_by_batches(graph):
    remaining_graph = graph.copy()
    batch_number = 1
    batches = []
    removed_edges = []

    while remaining_graph.nodes():
        # 找到当前出度为 0 的节点
        current_batch = [node for node, out_degree in remaining_graph.out_degree() if out_degree == 0]

        if not current_batch:
            # 找不到出度为 0 的节点，说明存在循环
            # 尝试移除一条边来打破循环
            edge = next(iter(remaining_graph.edges))
            removed_edges.append(edge)
            remaining_graph.remove_edge(*edge)
            print(f"Removed edge {edge} to break the cycle.")
            continue

        batches.append(f"第 {batch_number} 批函数: {', '.join(current_batch)}")

        # 移除当前批次的节点及其相关边
        remaining_graph.remove_nodes_from(current_batch)

        batch_number += 1

    if removed_edges:
        batches.append("以下边被移除来打破循环:")
        for edge in removed_edges:
            batches.append(f"{edge[0]} -> {edge[1]}")

    return batches


# 遍历所有函数并进行反编译
def decompile_all_functions():
    # 当前文件夹路径
    current_folder = os.getcwd()
    # 创建名为 'extract' 的文件夹（如果不存在）
    extract_folder = os.path.join(current_folder, 'extract')
    if not os.path.exists(extract_folder):
        os.makedirs(extract_folder)
    # 创建以二进制文件名称为名称的子文件夹
    binary_output_folder = os.path.join(extract_folder, file_name)
    if not os.path.exists(binary_output_folder):
        os.makedirs(binary_output_folder)

    # 获取当前程序的架构信息
    inf = idaapi.get_inf_structure()
    # 判断是 32 位还是 64 位
    if inf.is_64bit():
        efiXplorer_plugin = 'efiXplorer64'
    else:
        efiXplorer_plugin = 'efiXplorer'
    plugin = ida_loader.load_plugin(efiXplorer_plugin)
    ida_loader.run_plugin(plugin, 0)

    # 创建函数调用图
    graph = create_function_graph()
    # 获取函数调用关系
    call_relations = get_function_call_relations(graph)
    call_relations_file = os.path.join(binary_output_folder, 'function_call_relations.txt')
    with open(call_relations_file, 'w') as f:
        for relation in call_relations:
            f.write(relation + '\n')
    print(f"Function call relations saved to {call_relations_file}")
    # 获取按批次输出的函数信息
    batches_info = get_functions_by_batches(graph)
    batches_file = os.path.join(binary_output_folder, 'function_batches.txt')
    with open(batches_file, 'w') as f:
        for batch in batches_info:
            f.write(batch + '\n')
    print(f"Function batches saved to {batches_file}")

    # 遍历所有函数并进行反编译
    for func_start in idautils.Functions():
        decompile_function(func_start, binary_output_folder)


# 运行反编译所有函数的流程
decompile_all_functions()
