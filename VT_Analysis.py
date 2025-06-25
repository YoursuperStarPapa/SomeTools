#!/usr/bin/env python3
# coding:utf-8
'''
File VT_Analysis.py
Author Leo
Date:2025/6/25
'''


import vt
import time
import csv
import sys

API_KEY = ""  # API Key

# Query Type Support
QUERY_TYPES = ["file", "ip_address", "domain", "url"]

def query_vt(client, query_type, value):
    try:
        if query_type == "file":
            obj = client.get_object(f"/files/{value}")
        elif query_type == "ip_address":
            obj = client.get_object(f"/ip_addresses/{value}")
        elif query_type == "domain":
            obj = client.get_object(f"/domains/{value}")
        elif query_type == "url":
            obj = client.get_object(f"/urls/{vt.url_id(value)}")
        else:
            print(f"unknown error: {query_type}")
            return None
        return obj
    except vt.error.APIError as e:
        print(f"{query_type} {value} error: {e}")
        return None

def extract_info(obj, query_type, value):
    if not obj:
        return [value, "query fail", "", "", "", "", "", ""]
    stats = obj.last_analysis_stats if hasattr(obj, "last_analysis_stats") else {}
    malicious = stats.get("malicious", "")
    suspicious = stats.get("suspicious", "")
    undetected = stats.get("undetected", "")
    harmless = stats.get("harmless", "")
    total = sum(stats.values()) if stats else ""
    last_analysis = getattr(obj, "last_analysis_date", "")
    if last_analysis:
        import datetime
        if isinstance(last_analysis, (int, float)):
            last_analysis = datetime.datetime.utcfromtimestamp(last_analysis)
        if isinstance(last_analysis, datetime.datetime):
            last_analysis = last_analysis.strftime("%Y-%m-%d %H:%M:%S")
    link = ""
    if query_type == "file":
        link = f"https://www.virustotal.com/gui/file/{value}"
    elif query_type == "ip_address":
        link = f"https://www.virustotal.com/gui/ip-address/{value}"
    elif query_type == "domain":
        link = f"https://www.virustotal.com/gui/domain/{value}"
    elif query_type == "url":
        link = f"https://www.virustotal.com/gui/url/{vt.url_id(value)}"
    return [value, malicious, suspicious, undetected, harmless, total, last_analysis, link]

def main(input_file, query_type, output_file):
    with vt.Client(API_KEY) as client:
        with open(input_file, "r", encoding="utf-8") as f:
            values = [line.strip() for line in f if line.strip()]
        with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Query Value", "Malicious", "Suspicious", "Not Detected", "Harmless", "Total Detections", "Last Analysis Time", "VT Link" ])
            for value in values:
                print(f"Query: {query_type} - {value}")
                obj = query_vt(client, query_type, value)
                info = extract_info(obj, query_type, value)
                writer.writerow(info)
                time.sleep(3)  # Speed limit
                print(f"--> {info}")
                print("-" * 40)

if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[2] not in QUERY_TYPES:
        print(f"Usage: python {sys.argv[0]} [Filename] [Type: file/ip_address/domain/url] [output_csv]")
        exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])







if __name__ == '__main__':
    pass