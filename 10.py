import requests
import urllib3
from mailmerge import MailMerge
from docx import Document
from docx.enum.text import WD_BREAK

# 加载Word文档
template = "AWVS.docx"
document = MailMerge(template)
#document.add_page_break()  # 添加分页符

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 设置 API 地址和组 ID
api_url = 'https://172.21.5.27:3443/api/v1/scans'
group_id = '7b6d6dd0-3a99-406f-83c0-49f003ad3e89'

# 设置 API 认证信息
api_key = "1986ad8c0a5b3df4d7028d5f3c06e936ca723deb5d73441da9d991805c93bfd00"
headers = {"X-Auth": api_key}

# 发送 GET 请求获取任务信息
response = requests.get(f'{api_url}?group_id={group_id}', headers=headers, verify=False)

# 获取返回的 JSON 数据并提取 scan_id 和 scan_session_id
scan_data = response.json()['scans']
scan_id_list = [scan['scan_id'] for scan in scan_data]
scan_session_id_list = [scan['current_session']['scan_session_id'] for scan in scan_data]

# 定义数据列表
data_list = []
for scan_id, scan_session_id in zip(scan_id_list, scan_session_id_list):
    vulnerabilities_url = f'{api_url}/{scan_id}/results/{scan_session_id}/vulnerabilities'
    response = requests.get(vulnerabilities_url, headers=headers, verify=False)
    vulnerabilities_data = response.json()
    for vuln in vulnerabilities_data['vulnerabilities']:
        vuln_id = vuln['vuln_id']
        vuln_url = f'{api_url}/{scan_id}/results/{scan_session_id}/vulnerabilities/{vuln_id}'
        response = requests.get(vuln_url, headers=headers, verify=False)
        vuln_details = response.json()
        # 对cvss_score值进行判断
        if vuln_details['cvss_score'] >= 7.0:
            cvss_score_str = '高危'
        elif vuln_details['cvss_score'] >= 4.0:
            cvss_score_str = '中危'
        elif vuln_details['cvss_score'] >= 0.1:
            cvss_score_str = '低危'
        else:
            cvss_score_str = '信息'
        data_list.append({
            'vuln_id': vuln_id,
            'vt_name': vuln_details['vt_name'],
            'long_description': vuln_details['long_description'],
            'affects_detail': vuln_details['affects_detail'],
            'description': vuln_details['description'],
            'impact': vuln_details['impact'],
            'affects_url': vuln_details['affects_url'],
            'request': vuln_details['request'],
            'details': vuln_details['details'],
            'cvss_score': cvss_score_str,
            'recommendation': vuln_details['recommendation'],
            'references': vuln_details['references'],
        })

# 遍历数据列表，输出数据到文档中
for data in data_list:
    document.merge(
        vt_name=data['vt_name'],
        long_description=data['long_description'],
        affects_detail=data['affects_detail'],
        description=data['description'],
        impact=data['impact'],
        affects_url=data['affects_url'],
        request=data['request'],
        details=data['details'],
        cvss_score=str(data['cvss_score']),
        recommendation=data['recommendation'],
        references=data['references'],
    )

# 保存文档
document.write('output36.docx')

