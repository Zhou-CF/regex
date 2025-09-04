import concurrent.futures
import os
from concurrent.futures import FIRST_COMPLETED
import subprocess
import json
import argparse
import shutil
import tqdm


def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description='运行rule检查器脚本，无参数则是运行rule下所有脚本')
    parser.add_argument('-c', '--CVE', 
                       help='CVE编号的脚本（如CVE-1000-1000）')
    parser.add_argument('-p', '--path', 
                       default='.',
                       help='指定扫描文件路径（默认当前目录）')
    
    return parser.parse_args()

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

def merge_json_files(input_dir, output_file):
    """
    合并指定目录下的所有JSON文件到一个输出文件中。
    
    :param input_dir: 输入目录，包含多个JSON文件
    :param output_file: 输出文件路径
    """
    if not os.path.exists(input_dir):
        print(f"扫描目录不存在: {input_dir}")
        return

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

    # output_file = os.path.join(output_file, 'scan_res.json')
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(res, f, ensure_ascii=False, indent=4)

def run_checker(python_command, checker_path, file_path, output_path):
    """
    运行checkr脚本，检查项目中的漏洞。
    
    :param checer_path: checkr脚本的路径   
    :param project_path: 项目代码的路径
    :param output_path: 输出结果的路径
    """

    cmd = [python_command, checker_path, file_path]

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
            item["path"] = os.path.relpath(file_path)
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        write_vul_json(output_path, json_result)
        print(f"{file_path} 处理完毕，结果已保存到 {output_path}")
        return json_result
    except subprocess.TimeoutExpired:
        return None
    except subprocess.CalledProcessError as e:
        # print(f"Error processing {file_path}: {e.stderr}")
        return None 

def check_python_command(command):
    """检查Python命令是否可用，并返回版本信息"""
    try:
        # 检查命令是否存在
        if shutil.which(command) is None:
            return False, None
        
        # 获取Python版本
        result = subprocess.run(
            [command, "-V"], 
            capture_output=True, 
            text=True, 
            check=True
        )
        version = result.stdout.strip()
        return True, version
    except Exception:
        return False, None

def check_python_version():
    """检查Python版本是否符合要求"""
    for command in ['python3', 'python']:
        is_available, _ = check_python_command(command)
        if is_available:
            return command
    
    return None

    

def main(cve = None, path='.'):

    root_path = os.path.dirname(os.path.abspath(__file__))
    max_workers = 12  # 最大线程数
    futures = []

    # 检查Python版本
    python_command = check_python_version()
    if not python_command:
        print("未找到可用的Python命令，请检查Python安装。")
        return

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 遍历所有项目
        rule_path = os.path.join(root_path, 'rule')
            
        # 遍历每个CVE目录
        for cve_file in os.listdir(rule_path):

            # 指定CVE时只处理该CVE
            if cve and cve_file != cve:
                continue

            cve_path = os.path.join(rule_path, cve_file)
            if not os.path.isdir(cve_path):
                continue
            
            checker_path = os.path.join(cve_path, 'rule.py')
            if not os.path.exists(checker_path):
                continue
            
            sacn_res_path = os.path.join(cve_path, 'scan_res')
            if os.path.exists(sacn_res_path):
                continue

            if os.path.isfile(path):
                # 构建输出路径
                relative_file_path = os.path.relpath(path, root_path)
    
                output_file_path = os.path.join(sacn_res_path, relative_file_path.replace('/', '_').replace('\\', '_') + '.json')
                run_checker(checker_path, path, sacn_res_path)
            elif os.path.isdir(path):
                # 遍历源代码文件
                for root, dirs, files in tqdm.tqdm(os.walk(root_path)):
                    for file in files:
                        file_path = os.path.join(root, file)
                        if file_path.startswith(rule_path):
                            continue
                        # 构建输出路径
                        relative_file_path = os.path.relpath(file_path, root_path)
        
                        output_file_path = os.path.join(sacn_res_path, relative_file_path.replace('/', '_').replace('\\', '_') + '.json')

                        if os.path.exists(output_file_path):
                            continue
                            
                        # 关键控制：当活跃线程数达到最大值时等待
                        while len([f for f in futures if not f.done()]) >= max_workers:
                            # 等待至少一个任务完成
                            done, _ = concurrent.futures.wait(
                                futures, 
                                return_when=FIRST_COMPLETED,
                                timeout=5
                            )
                            # 移出已完成的任务
                            futures = [f for f in futures if not f.done()]
                            
                        # 提交新任务
                        future = executor.submit(
                            run_checker,
                            python_command, 
                            checker_path, 
                            file_path, 
                            output_file_path
                        )
                        futures.append(future)
        
                # 等待所有剩余任务完成
                concurrent.futures.wait(futures)
                # 合并所有扫描结果
                merge_json_files(sacn_res_path, os.path.join(cve_path, 'scan_res.json'))
            else:
                print(f"指定的路径 {path} 既不是文件也不是目录，请检查输入。")
                return
                

if __name__ == "__main__":
    args = parse_arguments()
    main(cve=args.CVE, path=args.path)