
**注意**

* patch文件夹下存放 项目->漏洞编号->补丁信息
* source_code文件夹下存放 项目的具体版本
* output 为正则规则输出的文件夹

最后需要人工根据补丁确认漏洞在源码中所在位置，按**输出样例**的格式来存在对应项目的源码、漏洞编号以及规则。

将项目的具体信息写入excel表中，如[cve_scan_result.xlsx](cve_scan_results.xlsx)所示

要求一个项目中至少涉及3中CWE

### 运行

将收集到的漏洞补丁按格式存放在 `patch` 文件夹下，源码存放在source_code文件夹下

然后`python main.py`可运行