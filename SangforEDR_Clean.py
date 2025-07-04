#!/usr/bin/env python3
# coding:utf-8
'''
File SangforEDR.py
Author Leo
Date:2025/6/17
'''
import json

import pandas as pd
import re


pattern = r'(<.*?>.*?: adv_threat_log :)'  # 分组方便后续引用


def quote_if_match(raw):
    match = re.search(pattern, str(raw))
    if match:
        cc = match.group(1)
        # 只替换第一个出现的部分，并用引号包裹
        return str(raw).replace(cc, f'"{cc}"', 1)
    return raw

def adv_threat_log():
    try:
        patterns = {

            "oid": r'"\$oid":"(.*?)"',
            "severity": r'"alert_level":([0-9]),',
            "alert_describe": r'"alert_describe":"(.*?)","match_pros"',
            "rule_name": r'"rule_name":"(.*?)","rule_desc"',
            "process_mame": r'"process_mame ":"(.*?)"',
            "command": r'"command":"(.*?)"}]',
            "endpoint": r'"endpoint":"(.*?)"',
            "host_name": r'"host_name":"(.*?)"',
            "ip": r'"iplist":"(.*?)"',
        }

        return patterns

    except Exception as e:
        print(e)

def nofile_attack():
    try:
        patterns = {
            "Alert_type": r'\<.*?\>.*?\sEDR\.\[.*?\]\:\s(.*?)\s\:\s\[\{',
            "oid": r'"_id":"(.*?)",',
            "threat_name": r'"threat_name":"(.*?)",',
            "state": r'"state":"(.*?)",',
            "threat_process": r'"threat_process": "(.*?)",',
            "process_detail": r'"threat_process_params":"(.*?)",\"agent_id\"',
            "endpoint": r'"endpoint":"(.*?)"',
            "host_name": r'"host_name":"(.*?)",',
            "ip": r'"iplist":"(.*?)"'


        }

        return patterns



    except Exception as e:
        print(e)

def virus_event():
    try:
        patterns = {
            "Alert_type": r'\<.*?\>.*?\sEDR\.\[.*?\]\:\s(.*?)\s\:\s\[\{',
            "oid": r'"_id":"(.*?)",',
            "virus_name": r'"virus_name":"(.*?)",',
            "risk_level": r'"risk_level":"(.*?)",',
            "virus_type": r'"virus_type": "(.*?)",',
            "threat_file": r'"threat_file":"(.*?)"',
            "state": r'"state":"(.*?)"',
            "file_md5": r'"file_md5":"(.*?)"',
            "file_path": r'"file_path":"(.*?)","file_size"',
            "endpoint": r'"endpoint":"(.*?)"',
            "host_name": r'"host_name":"(.*?)",',
            "ip": r'"iplist":"(.*?)"'
        }

        return patterns

    except Exception as e:
        print(e)



def main():

    file_path = "Qradar export/2025-07-04-data_export.csv"
    df = pd.read_csv(file_path)

    for col, pat in adv_threat_log().items():
        df[col] = df['raw log'].apply(
            lambda raw: re.search(pat, str(raw)).group(1) if re.search(pat, str(raw)) else None)



    print(df['raw log'])

    # 保存回原CSV（如需备份请改文件名）
    df.to_csv(file_path, index=False)

    # 保存为新的Excel或CSV
    # df.to_excel("Qradar export/Qradar_export_fields.xlsx", index=False)
    # df.to_csv("Qradar_export_fields.csv", index=False)





if __name__ == '__main__':
    # adv_threat_log()
    main()