#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess
import time
import threading
import glob
import re

from collections import defaultdict
from pathlib import Path
from multiprocessing import Pool

from PCTFuzzer import *
from SymccAFLpp import *
from AFLplusplus import *
from AFL import *

JHEAD_CONFIG = {
    "project_name": "jhead-3.08",
    "project_dir" : "/home/aaa/FPCT/bench/jhead-3.08",
    "build_cmd": ["make"],
    "clean_cmd": ["make", "clean"],
    "binary_name": "jhead",
    "input_args": ["@@"],
}

def get_fuzzer(tool_name, project_name, private_src, binary_name,
        build_cmd, clean_cmd, input_args, work_dir, time_out):
    if tool_name == "PCTFuzzer":
        fuzzer = PCTFuzzer(project_name, private_src, binary_name, 
                           build_cmd, clean_cmd, input_args,
                           work_dir, time_out)
        return fuzzer
    elif tool_name == "AFLplusplus":
        fuzzer = AFLplusplus(project_name, private_src, binary_name, 
                             build_cmd, clean_cmd, input_args,
                             work_dir, time_out)
        return fuzzer
    elif tool_name == "AFL":
        fuzzer = AFL(project_name, private_src, binary_name, 
                     build_cmd, clean_cmd, input_args,
                     work_dir, time_out)
        return fuzzer
    elif tool_name == "SymccAFLpp":
        fuzzer = SymccAFLpp(project_name, private_src, binary_name, 
                            build_cmd, clean_cmd, input_args,
                            work_dir, time_out)
        return fuzzer
    return None
    
def run_single_work(base_dir, tool_name, run_index, config_map, time_out):
    project_name = config_map["project_name"]
    project_dir  = config_map["project_dir"]
    binary_name  = config_map["binary_name"]
    build_cmd    = config_map["build_cmd"]
    clean_cmd    = config_map["clean_cmd"]
    input_args   = config_map["input_args"]

    # work_dir : /home/aaa/FPCT/PCTFuzz/project_name/run_N
    work_dir = os.path.join(
        base_dir,
        tool_name,
        project_name,
        f"run_{run_index}"
    )
    os.makedirs(work_dir, exist_ok=True)
    
    private_src = os.path.join(
        work_dir,
        project_name,
    )
    
    # copy source to work_dir for compile
    shutil.copytree(project_dir, private_src, dirs_exist_ok=True)
    
    print(f"[Worker {run_index}] Work dir: {work_dir}")
    
    fuzzer = get_fuzzer(tool_name, project_name, private_src, binary_name,
                        build_cmd, clean_cmd, input_args, work_dir, time_out)
    
    fuzzer.run()


def parse_edges_from_plot(plot_path):
    """从 plot_data 文件中提取最后一行的 edges_found（第13列，索引12）"""
    try:
        with open(plot_path, 'r') as f:
            lines = f.readlines()

        data_lines = [line.strip() for line in lines if line.strip() and not line.startswith('#')]
        if not data_lines:
            return None

        last_line = data_lines[-1]
        fields = last_line.split(',')
        if len(fields) < 13:
            return None

        edges_str = fields[12].strip()
        edges_str = re.sub(r'[^\d]', '', edges_str)
        if not edges_str:
            return None
        return int(edges_str)
    except Exception as e:
        print(f"[!] Error reading {plot_path}: {e}")
        return None

def run_analyze(BASE_DIR, TOOLS, CONFIGS, RUNS):
    results = defaultdict(lambda: defaultdict(list))

    for tool in TOOLS:
        for config in CONFIGS:
            project_name = config["project_name"]
            for run_id in range(1, RUNS + 1):
                pattern = os.path.join(
                    BASE_DIR, tool, project_name, f"run_{run_id}",
                    "fuzz_out", "afl-master", "plot_data")
                matches = glob.glob(pattern)
                if not matches:
                    print(f"[!] No plot_data found for {tool}/{project}/run_{run_id}")
                    continue
                if len(matches) > 1:
                    print(f"[!] Multiple plot_data found for {tool}/{project}/run_{run_id}, using first: {matches[0]}")
                plot_file = matches[0]

                edges = parse_edges_from_plot(plot_file)
                if edges is not None:
                    results[tool][project_name].append(edges)
                else:
                    print(f"[!] Failed to parse edges from {plot_file}")

    print("\n" + "="*60)
    print("Average edges_found per tool (over {} runs):".format(RUNS))
    print("="*60)
    for tool in TOOLS:
       for config in CONFIGS:
            project_name = config["project_name"]
            edges_list = results[tool][project_name]
            if not edges_list:
                avg = 0
                count = 0
            else:
                avg = sum(edges_list) / len(edges_list)
                count = len(edges_list)
            print(f"{tool:<15} | {project_name:<12} | Avg edges: {avg:8.2f} | Valid runs: {count}/{RUNS}")

def run_expriments(BASE_DIR, TOOLS, CONFIGS, TIMEOUT, process_num, RUNS):
    task_list = []
    for tool in TOOLS:
        for config in CONFIGS:
            for i in range(1, RUNS + 1):
                task_list.append((BASE_DIR, tool, i, config, TIMEOUT))

    with Pool(processes=process_num) as pool:
        try:
            pool.starmap(run_single_work, task_list)
        except KeyboardInterrupt:
            print("\n[!] Received Ctrl+C, terminating workers...")
            pool.terminate()
            pool.join()
        else:
            pool.close()
            pool.join()

    print(f"[+] All {len(task_list)} runs completed.")

def main():
    BASE_DIR = "/home/aaa/FPCT/multi_run"
    
    #TOOLS   = ["PCTFuzzer", "SymccAFLpp", "AFLplusplus"]
    TOOLS   = ["PCTFuzzer"]
    CONFIGS = [JHEAD_CONFIG]
    TIMEOUT = 200

    process_num = 2
    RUNS   = 1
    
    run_expriments(BASE_DIR, TOOLS, CONFIGS, TIMEOUT, process_num, RUNS)
    #run_analyze(BASE_DIR, TOOLS, CONFIGS, RUNS)

if __name__ == "__main__":
    main()
