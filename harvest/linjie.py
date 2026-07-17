import idaapi
import idautils
import idc
import networkx as nx

# 创建一个函数图
def create_function_graph():
    graph = nx.DiGraph()

    # 遍历所有的函数
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        graph.add_node(func_name)

        # 遍历当前函数中的指令，查找调用其他函数的指令
        for head in idautils.Heads(func_ea, idc.get_func_attr(func_ea, idc.FUNCATTR_END)):
            mnem = idc.print_insn_mnem(head)
            if mnem == "call":
                # 获取被调用的函数
                called_func_ea = idc.get_operand_value(head, 0)
                called_func_name = idc.get_func_name(called_func_ea)
                if called_func_name:
                    graph.add_edge(func_name, called_func_name)

    return graph

# 输出邻接矩阵并计算入度和出度
def print_adjacency_matrix_with_degrees(graph):
    func_list = list(graph.nodes)
    matrix = [[0] * len(func_list) for _ in range(len(func_list))]

    # 计算每个函数的入度和出度
    in_degrees = {func: graph.in_degree(func) for func in func_list}
    out_degrees = {func: graph.out_degree(func) for func in func_list}

    # 填充邻接矩阵
    func_index = {func: idx for idx, func in enumerate(func_list)}
    for source, target in graph.edges:
        matrix[func_index[source]][func_index[target]] = 1

    # 打印邻接矩阵和入度、出度
    print(f"邻接矩阵 (大小: {len(func_list)}x{len(func_list)}):")
    print(" " * 12 + " ".join([f"{func: <10}" for func in func_list]) + " 入度 出度")
    
    for i, row in enumerate(matrix):
        row_str = " ".join(map(str, row))
        print(f"{func_list[i]: <10} {row_str} {in_degrees[func_list[i]]} {out_degrees[func_list[i]]}")

def main():
    # 创建函数调用图
    graph = create_function_graph()

    # 输出邻接矩阵和计算入度、出度
    print_adjacency_matrix_with_degrees(graph)

# 执行主函数
if __name__ == "__main__":
    main()
