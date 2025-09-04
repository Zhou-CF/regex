import os
import re
from src import utils, model, prompt
import tqdm
import json
import shutil
from dotenv import load_dotenv

load_dotenv()

patch_root = os.getenv('PATCH_DIR', r'E:\项目\内置漏洞\正则\patch')
output_root = os.getenv('OUTPUT_DIR', r'E:\项目\内置漏洞\正则\output')
source_root = os.getenv('SOURCE_CODE_DIR', r'E:\项目\内置漏洞\正则\source_code')

client = model.LLMClient()

def extract_python_code(text):
    """
    从文本中提取所有被 ```python ... ``` 包裹的代码块
    支持多行代码块和单行代码块
    自动去除代码块前后的空白字符

    :param text: 输入文本
    :return: 提取的代码块列表
    """
    # 匹配多行代码块（结束标记单独一行）
    multi_line_pattern = r'```python\s*?\n?(.*?)\n\s*```'
    # 匹配单行代码块（开始和结束标记在同一行）
    single_line_pattern = r'```python\s*?([^\n]*?)```'
    
    # 使用DOTALL标志确保.匹配换行符
    multi_line_blocks = re.findall(multi_line_pattern, text, re.DOTALL)
    # 单行代码不需要DOTALL
    single_line_blocks = re.findall(single_line_pattern, text)
    
    # 合并结果并去除前后空白
    all_blocks = [block.strip() for block in multi_line_blocks + single_line_blocks]
    return all_blocks

def analyze_cve(patch_path):
    """
    分析补丁文件

    :param patch_path: 补丁文件路径
    :return: 分析结果
    """
    patch_content = utils.read_file(patch_path)
    PY_PROMPT = prompt.ONLY_PATCH_PY.format(patch_content=patch_content)
    response = client.send_messages(PY_PROMPT)
    return response.content

def analyze_cve_again(patch_path, code_path):
    """
    正则匹配不到结果，迭代正则规则

    :param patch_path: 补丁文件路径
    :param code_path: 正则规则文件路径
    :return: 分析结果
    """
    patch_content = utils.read_file(patch_path)
    code_content = utils.read_file(code_path)
    PY_PROMPT = prompt.FIX_ERR_REGEX_ONLYPATCH_PY.format(patch_content=patch_content, code=code_content)
    response = client.send_messages(PY_PROMPT)
    return response.content

def analyze_cve_again_too_much(patch_path, code_path):
    """
    正则匹配到的结果过多， 迭代正则规则

    :param patch_path: 补丁文件路径
    :param code_path: 正则规则文件路径
    :return: 分析结果
    """
    # print(f"analyze_cve_again: {patch_path}, {code_path}")
    patch_content = utils.read_file(patch_path)
    code_content = utils.read_file(code_path)
    PY_PROMPT = prompt.FIX_REGEX_ONLYPATCH_PY.format(patch_content=patch_content, code=code_content)
    response = client.send_messages(PY_PROMPT)
    return response.content

def save_rule_py(project_name, cve_name, code, patch_name=None):
    """
    保存规则文件

    :param project_name: 项目名称
    :param cve_name: CVE名称
    :param code: 规则代码
    :param patch_name: 补丁名称
    """
    save_dir = os.path.join(output_root, project_name, 'rule', cve_name)
    os.makedirs(save_dir, exist_ok=True)
    
    if patch_name:
        # 如果指定了补丁名称，则为每个补丁单独保存文件
        safe_patch_name = re.sub(r'[^\w\-_.]', '_', patch_name)  # 清理文件名
        save_path = os.path.join(save_dir, f'rule_{safe_patch_name}.py')
    else:
        save_path = os.path.join(save_dir, 'rule.py')
    
    with open(save_path, 'w', encoding='utf-8') as f:
        f.write(code)
    # print(f"保存规则文件: {save_path}")

def deal(patch_path, project_name, cve_name, patch_name=None):
    """
    保存规则文件

    :param project_name: 项目名称
    :param cve_name: CVE名称
    :param code: 规则代码
    :param patch_name: 补丁名称
    """
    try:
        response_text = analyze_cve(patch_path)
    except Exception as e:
        print(f"分析补丁 {patch_path} 时出错: {e}")
        return
    code_blocks = extract_python_code(response_text)
    code = max(code_blocks, key=len) if code_blocks else None
    if code:
        save_rule_py(project_name, cve_name, code, patch_name)
    else:
        print(f"未提取到python代码: {patch_path}")

def check_rule_py(project_name, cve_name):
    """
    根据规则文件检查源码

    :param project_name: 项目名称
    :param cve_name: CVE名称
    """
    save_dir = os.path.join(output_root, project_name, 'rule', cve_name)
    print(f"检查目录: {save_dir}")
    if not os.path.exists(save_dir):
        return False

    rule_file = os.path.join(save_dir, 'rule.py')
    print(f"检查规则文件: {rule_file}")
    if not os.path.exists(rule_file):
        print(f"规则文件不存在: {rule_file}")
        return False
    source_code = utils.get_source_directory(source_root, project_name)
    print("源码文件：", source_code)
    if not source_code:
        print(f"源码目录不存在: {source_code}")
        return False
    patch_dir = os.path.join(patch_root, project_name, cve_name)
    for patch_info in os.listdir(patch_dir):
        print(os.path.join(patch_dir, patch_info))

    utils.moreThead_run_checker(rule_file, source_code, save_dir)

def check_main():
    for project_name in os.listdir(patch_root):
        project_path = os.path.join(patch_root, project_name)
        if not os.path.isdir(project_path):
            continue
        for cve_name in os.listdir(project_path):
            cve_path = os.path.join(project_path, cve_name)
            if not os.path.isdir(cve_path):
                continue
            check_rule_py(project_name, cve_name)

def find_project(project):
    for proj in os.listdir(source_root):
        if proj.lower().startswith(project.lower()):
            return proj
    return None

def main(project:str=None):
    for project_name in tqdm.tqdm(os.listdir(patch_root)):
        if project and project_name.lower() != project.lower():
            continue
        else:
            project_output_dir = os.path.join(output_root, project_name)
            if os.path.exists(project_output_dir):
                print(f"项目已存在，跳过处理: {project_name}")
                continue

        project_path = os.path.join(patch_root, project_name)
        if not os.path.isdir(project_path):
            continue
        for cve_name in tqdm.tqdm(os.listdir(project_path)[:8], desc=f"Processing {project_name}", leave=False):
            if cve_name.startswith(project_name):
                continue
            cve_path = os.path.join(project_path, cve_name)
            if not os.path.isdir(cve_path):
                continue

            save_dir = os.path.join(output_root, project_name, 'rule', cve_name)

            patch_files = [f for f in os.listdir(cve_path) if os.path.isfile(os.path.join(cve_path, f))]

            # print(f"\n处理CVE: {project_name}/{cve_name}, 发现 {len(patch_files)} 个补丁文件")
            if len(patch_files) == 1:
                save_path = os.path.join(save_dir, 'rule.py')
                if os.path.exists(save_path):
                    # print(f"已存在规则文件: {save_path}，跳过处理")
                    continue
                # print(f"只有一个补丁文件，直接处理: {cve_path}")
                for patch_info in patch_files:
                    patch_info_path = os.path.join(cve_path, patch_info)
                    deal(patch_info_path, project_name, cve_name)
            else:
                for patch_info in patch_files:
                    safe_patch_name = re.sub(r'[^\w\-_.]', '_', patch_info)  # 清理文件名
                    save_path = os.path.join(save_dir, f'rule_{safe_patch_name}.py')
                    if os.path.exists(save_path):
                        # print(f"已存在规则文件: {save_path}，跳过处理")
                        continue
                    patch_info_path = os.path.join(cve_path, patch_info)
                    deal(patch_info_path, project_name, cve_name, patch_info)
        source_code_path = utils.get_source_directory(source_root, project_name)
        proj = os.path.basename(source_code_path) if source_code_path else project_name
        if source_code_path:
            shutil.copytree(source_code_path, os.path.join(output_root, project_name, proj), dirs_exist_ok=True)
        shutil.copy(r'./run.py', os.path.join(output_root, project_name))

def update_a_cve_res_too_much(project, cve):
    """
    CVE的规则检测结果过多，进行迭代，并重新根据规则进行检查

    :param project_name: 项目名称
    :param cve_name: CVE名称
    """
    check_code_path = os.path.join(output_root, project, 'rule', cve)
    if not os.path.exists(check_code_path):
        return
    code_path = os.path.join(check_code_path, 'rule.py')
    print(code_path)
    patch_path = os.path.join(patch_root, project, cve, os.listdir(os.path.join(patch_root, project, cve))[0])
    new_code_content = analyze_cve_again_too_much(patch_path, code_path)
    new_code = extract_python_code(new_code_content)
    if not new_code:
        return

    update_code_path = os.path.join(check_code_path, 'rule.py')
    with open(update_code_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_code))

    source_code_path = utils.get_source_directory(source_root, project)
    if not source_code_path:
        return

    print('源码', source_code_path)
    print('更新后的代码', update_code_path)
    print('补丁文件', patch_path)

    utils.moreThead_run_checker(
        update_code_path, 
        source_code_path, 
        check_code_path
    )

    output_merge_path = os.path.join(check_code_path, 'scan_res.json')
    cont = utils.read_json(output_merge_path)
    if len(cont) > 50:
        print(f"漏洞过多 {project} - {cve}")
        return

    patch_content = utils.read_file(patch_path)
    utils.check_patch_with_llm(
        os.path.join(update_code_path, 'scan_res'), 
        patch_content, 
        source_code_path
    )

def update_a_cve(project, cve, commit=None):
    """
    CVE的规则检测不到结果，进行迭代，并重新根据规则进行检查

    :param project_name: 项目名称
    :param cve_name: CVE名称
    :param commit: 指定commit的补丁，默认不指定，一般是一个洞有多个补丁
    """

    check_code_path = os.path.join(output_root, project, cve)
    print(f"检查代码路径: {check_code_path}")
    if not os.path.exists(check_code_path):
        return
    code_path = os.path.join(check_code_path, 'rule.py')                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
    print(code_path)
    if commit:
        patch_path = os.path.join(patch_root, project, cve, f"{commit}.patch")
    else:
        patch_path = os.path.join(patch_root, project, cve, os.listdir(os.path.join(patch_root, project, cve))[0])
    new_code_content = analyze_cve_again(patch_path, code_path)
    new_code = extract_python_code(new_code_content)
    if not new_code:
        return



    update_code_path = os.path.join(check_code_path, 'rule.py')
    with open(update_code_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_code))

    source_code_path = utils.get_source_directory(source_root, project)
    if not source_code_path:
        return

    print('源码', source_code_path)
    print('更新后的代码', update_code_path)
    print('补丁文件', patch_path)

    utils.moreThead_run_checker(
        update_code_path, 
        source_code_path, 
        check_code_path
    )

    output_merge_path = os.path.join(check_code_path, 'scan_res.json')
    cont = utils.read_json(output_merge_path)
    if len(cont) > 50:
        print(f"漏洞过多 {project} - {cve}")
        return

    patch_content = utils.read_file(patch_path)
    utils.check_patch_with_llm(
        os.path.join(check_code_path, 'scan_res'), 
        patch_content, 
        source_code_path
    )


if __name__ == "__main__":
    main()