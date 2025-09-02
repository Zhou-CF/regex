import os
import json
import subprocess
import pandas as pd
import concurrent.futures

def read_file(file_path):
    """
    读取文件内容并返回字符串。
    :param file_path: 文件路径
    :return: 文件内容字符串
    """
    if not os.path.exists(file_path):
        return None
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

def write_file(file_path, content):
    """
    将字符串内容写入文件。
    :param file_path: 文件路径
    :param content: 要写入的内容字符串
    """
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

def read_json(file_path):
    """
    读取JSON文件并返回Python对象。
    :param file_path: JSON文件路径
    :return: Python对象
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

def write_json(file_path, data):
    """
    将Python对象写入JSON文件。
    :param file_path: JSON文件路径
    :param data: 要写入的Python对象
    """
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=4)

def get_source_directory(source_root, project):
    """
    获取源代码目录下所有项目的路径。
    
    :param source_root: 源代码根目录
    :param project: 项目名称
    :return: 包含所有项目路径的列表
    """
    for item in os.listdir(source_root):
        if item.lower().startswith(project.lower()):
            return os.path.join(source_root, item)


source_root = r'E:\项目\内置漏洞\529新增项目\source_code'

def write_vul_json(file_path, data):
    """
    将Python对象写入JSON文件。
    
    :param file_path: JSON文件路径
    :param data: 要写入的Python对象
    """
    if os.path.exists(file_path):
        # 如果文件已存在，先读取内容
        with open(file_path, 'r', encoding='utf-8') as file:
            existing_data = json.load(file)
        # 合并新数据和现有数据
        if isinstance(existing_data, list):
            existing_data.extend(data)
        else:
            existing_data = [existing_data] + data
        data = existing_data
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=4)

def run_checker(checker_path, file_path, output_path):
    """
    运行checkr脚本，检查项目中的漏洞。
    
    :param checer_path: checkr脚本的路径   
    :param project_path: 项目代码的路径
    :param output_path: 输出结果的路径
    """

    cmd = ['python', checker_path, file_path]
    # print(f"Running command: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=10)
        json_result = json.loads(result.stdout.strip())
        # print(json_result)

        if not json_result:
            return None
        if isinstance(json_result, dict):
            json_result = [json_result]
        json_result = [item for item in json_result if 'loc' in item and item['loc'] != '0']
        if not json_result:
            return None

        for item in json_result:
            item["path"] = os.path.relpath(file_path, source_root)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        write_vul_json(output_path, json_result)
        # print(f"{file_path} 处理完毕，结果已保存到 {output_path}")
        return json_result
    except subprocess.TimeoutExpired:
        return None
    except subprocess.CalledProcessError as e:
        # print(f"Error processing {file_path}: {e.stderr}")
        return None 

def output_to_excel(data, output_file):
    """
    将数据输出到Excel文件。
    
    :param data: 要输出的数据，格式为列表或字典
    :param output_file: 输出的Excel文件路径
    """
    if not os.path.exists(os.path.dirname(output_file)):
        os.makedirs(os.path.dirname(output_file))
    df = pd.DataFrame(data[1:], columns=data[0])
    df.to_excel(output_file, index=False, engine='openpyxl')


def merge_json_files(input_dir, output_file):
    """
    合并指定目录下的所有JSON文件到一个输出文件中。
    
    :param input_dir: 输入目录，包含多个JSON文件
    :param output_file: 输出文件路径
    """
    res = []
    for file in os.listdir(input_dir):
        file_path = os.path.join(input_dir, file)
        if not file.endswith('.json'):
            continue
   
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = json.load(f)
        except json.JSONDecodeError as e:
            print(f"\t\tError reading {file_path}: {e}")
            break
    
        res.extend(content)
    print(f"合并结果数量: {len(res)}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(res, f, ensure_ascii=False, indent=4)


def moreThead_run_checker(checker_path, file_dir, output_dir):
    """
    使用多线程运行checker脚本，检查项目中的漏洞。
    
    :param checker_path: checker脚本的路径
    :param file_dir: 项目代码的目录
    :param output_dir: 输出结果的目录
    """
    scan_res_path = os.path.join(output_dir, 'scan_res')

    if not os.path.exists(scan_res_path):
        os.makedirs(scan_res_path)
    max_workers = 12  # 最大线程数
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for root, dirs, files in os.walk(file_dir):
            for file in files:
                file_path = os.path.join(root, file)

                relative_file_path = os.path.relpath(file_path, file_dir)

                output_file_path = os.path.join(scan_res_path, relative_file_path.replace('/', '_').replace('\\', '_') + '.json')
                if os.path.exists(output_file_path):
                    continue
                # 关键控制：当活跃线程数达到最大值时等待
                # print(checker_path, file_path, output_file_path)
                while len([f for f in futures if not f.done()]) >= max_workers:
                    # 等待至少一个任务完成
                    done, _ = concurrent.futures.wait(
                        futures, 
                        return_when=concurrent.futures.FIRST_COMPLETED,
                        timeout=10
                    )
                    # 移出已完成的任务
                    futures = [f for f in futures if not f.done()]
                    
                # 提交新任务
                future = executor.submit(
                    run_checker, 
                    checker_path, 
                    file_path, 
                    output_file_path
                )
                futures.append(future)

        # 等待所有任务完成
        concurrent.futures.wait(futures)
        merge_json_files(scan_res_path, os.path.join(output_dir, 'scan_res.json'))


def get_line_content(file_path, line_number):
    """
    获取指定文件中指定行号前后3行的内容。
    
    :param file_path: 文件路径
    :param line_number: 行号（从1开始）
    :return: 指定行的内容
    """
    line_number = int(line_number)  # 确保行号是整数
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
        start = max(0, line_number - 4)
        end = min(len(lines), line_number + 3)
        return ''.join(lines[start:end])
