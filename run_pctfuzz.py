#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess
import time
import threading
from pathlib import Path
import argparse

pctfuzzer_bin  = "/home/aaa/FPCT/PCTFuzz/cmake-build-debug/transform/PCTFuzzer"
symcc_compiler = "/home/aaa/FPCT/PCTFuzz/cmake-build-debug/symcc"

class PCTFuzzRunner:
    def __init__(self, project_name, project_dir, binary_name, build_cmd, clean_cmd, input_args, work_dir):
        self.project_name = project_name
        self.project_dir  = project_dir
        self.binary_name  = binary_name
        self.build_cmd    = build_cmd
        self.clean_cmd    = clean_cmd
        self.input_args   = input_args

        self.work_dir   = work_dir
        self.input_dir  = Path(os.path.join(work_dir, "fuzz_in"))
        self.output_dir = Path(os.path.join(work_dir, "fuzz_out"))
        self.binary_dir = Path(os.path.join(work_dir, "pct_bin"))

        self.src_bin   = Path(os.path.join(self.project_dir, binary_name))
        self.afl_bin   = Path(os.path.join(self.binary_dir, binary_name+"_afl"))
        self.symcc_bin = Path(os.path.join(self.binary_dir, binary_name+"_symcc"))

        self.pct_evaluator_so  = Path(os.path.join(self.binary_dir, "pct-evaluator.so"))
        self.pct_cfg_path = Path(os.path.join(self.binary_dir, binary_name+"_pct.cfg"))
        
        self.afl_proc = None
        self.pct_proc = None
        self.pct_stderr_thread = None

        self._validate()

    def _validate(self):
        if not Path(self.project_dir).exists():
            raise FileNotFoundError(f"Source directory not found: {self.project_dir}")
        if not Path(pctfuzzer_bin).exists():
            raise FileNotFoundError(f"PCTFuzzer binary not found: {pctfuzzer_bin}")
        if not Path(symcc_compiler).exists():
            raise FileNotFoundError(f"SymCC compiler not found: {symcc_compiler}")

    def prepare_dirs(self):
        print("[*] Preparing directories...")
        for d in [self.input_dir, self.output_dir]:
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(parents=True, exist_ok=True)

        seed_file = self.input_dir / "seed0"
        with open(seed_file, "wb") as f:
            f.write(b"A" * 20)

        print(f"[+] Generated fixed seed (20 bytes) at {seed_file}")

    def run_shell_cmd(self, cmd_str, cwd, env):
        """Run a shell command string (supports &&, pipes, etc.)"""
        print(f"    Running: {cmd_str} in {cwd}")
        result = subprocess.run(
            cmd_str,
            shell=True,
            cwd=cwd,
            env=env,
            check=True,
            text=True
        )
        return result

    def compile_afl_binary(self):
        print("[*] Compiling AFL++ binary...")
        env = os.environ.copy()
        env.update({
            "CC": "afl-clang-lto",
            "CXX": "afl-clang-lto++",
        })

        # Clean
        self.run_shell_cmd(self.clean_cmd, self.project_dir, env)
        # Build
        self.run_shell_cmd(self.build_cmd, self.project_dir, env)

        if not self.src_bin.exists():
            raise FileNotFoundError(f"Binary not found after build: {self.src_bin}")
        shutil.copy(self.src_bin, self.afl_bin)
        print(f"[+] AFL binary: {self.afl_bin}")

    def compile_symcc_binary(self):
        print("[*] Compiling SymCC binary...")
        env = os.environ.copy()
        env.update({
            "CC":  symcc_compiler,
            "CXX": symcc_compiler,
            "PCT_CFG_PATH": str(self.pct_cfg_path),
        })

        self.run_shell_cmd(self.clean_cmd, self.project_dir, env)
        self.run_shell_cmd(self.build_cmd, self.project_dir, env)

        if not self.src_bin.exists():
            raise FileNotFoundError(f"SymCC binary not found: {self.src_bin}")
        shutil.copy(self.src_bin, self.symcc_bin)
        print(f"[+] SymCC binary: {self.symcc_bin}")

    def start_afl(self, isRestart):
        print("[*] Starting AFL++ master...")
        env = os.environ.copy()
        env.update({
            "AFL_NO_UI": "1",
            #"AFL_NO_AFFINITY": "1",
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
            "AFL_SKIP_CRASHES": "1",
            "AFL_NO_FASTRESUME": "1",
            "AFL_AUTORESUME" : "1",
        })
        
        if isRestart:
            env.update({"AFL_AUTORESUME" : "1"})

        cmd = [
            "afl-fuzz",
            "-M", "afl-master",
            "-i", str(self.input_dir),
            "-o", str(self.output_dir),
            "--", str(self.afl_bin)
        ]
        cmd.extend(self.input_args)

        self.afl_proc = subprocess.Popen(
            cmd, env=env,  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"[+] AFL++ started (PID: {self.afl_proc.pid})")
        
    def stop_afl(self):
        print("[*] Stop AFL++ ......")
        if self.afl_proc and self.afl_proc.poll() is None:
            self.afl_proc.terminate()
            try:
                self.afl_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.afl_proc.kill()
                self.afl_proc.wait()
        time.sleep(1)

    def start_pctfuzzer(self):
        print("[*] Starting PCTFuzzer...")
        env = os.environ.copy()
        env["PCT_CFG_PATH"] = str(self.pct_cfg_path)

        afl_master_dir = self.output_dir / "afl-master"
        for _ in range(10):
            if afl_master_dir.exists():
                break
            time.sleep(1)
        else:
            raise RuntimeError("AFL master dir not created in 10s")

        cmd = [
            pctfuzzer_bin,
            "--fuzzer-name=afl-master",
            f"--output-dir={self.output_dir}",
            str(self.symcc_bin)
        ]

        self.pct_proc = subprocess.Popen(
            cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, universal_newlines=False
        )
        print(f"[+] PCTFuzzer started (PID: {self.pct_proc.pid})")

        self.pct_stderr_thread = threading.Thread(target=self.monitor_pct_stderr, daemon=True)
        self.pct_stderr_thread.start()

    def monitor_pct_stderr(self):
        try:
            while self.pct_proc.poll() is None:
                line = self.pct_proc.stderr.readline()
                if not line:
                    break
                line_str = line.decode('utf-8', errors='replace').strip()
                print(line_str)

                if "[STOP AFL]" in line_str:
                    self.stop_afl()
                    
                    if ":" in line_str:
                        print("[+] PCTFuzz create new evaluator ......")
                        src_path = line_str.split(":", 1)[1].strip()   
                        self.compile_evaluator_from(src_path)
                    else:
                        print("[+] PCTFuzz seed synchronization ......")
                        
                    time.sleep(3)
                    self.start_afl(True) 
               
        except Exception as e:
            print(f"[ERROR] Monitor error: {e}")

    def compile_evaluator_from(self, c_file):
        cmd = [
            "gcc", "-O3", "-funroll-loops", "-g", "-shared", "-fPIC",
            c_file, "-o", str(self.pct_evaluator_so)
        ]
        subprocess.run(cmd, check=True)
        print(f"[+] Evaluator compiled: {self.pct_evaluator_so}")

    def run(self):
        print(f"[+] Starting PCTFuzz for project: {self.project_name}")
        print("[+] Hybrid fuzzing running!")
        print(f"   Project: {self.project_name}")
        print(f"   AFL Output: {self.output_dir}/afl-master")
        print( "   Press Ctrl+C to stop...\n")

        self.prepare_dirs()
        #self.compile_afl_binary()
        #self.compile_symcc_binary()

        self.start_afl(False)
        time.sleep(5)
        self.start_pctfuzzer()

        try:
            while True:
                if self.pct_proc.poll() is None or self.afl_proc.poll() is None:
                    time.sleep(1)
                else:
                    print("[!] A process exited.")
                    break
        except KeyboardInterrupt:
            print("\n[!] Interrupt received.")
        finally:
            self.stop()

    def stop(self):
        print("[*] Shutting down...")
        for name, proc in [("AFL++", self.afl_proc), ("PCTFuzzer", self.pct_proc)]:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except:
                    proc.kill()
        print("[+] Done.")

JHEAD_CONFIG = {
    "project_name": "jhead-3.08",
    "project_dir" : "/home/aaa/FPCT/bench/jhead-3.08",
    "build_cmd": ["make"],
    "clean_cmd": ["make", "clean"],
    "binary_name": "jhead",
    "input_args": ["@@"],  # 或 "-f", "@@" 等，根据 target 调整
}

def main():
    #args = parse_args()
    work_dir = "/home/aaa/FPCT/bench/"
    runner = PCTFuzzRunner(
        JHEAD_CONFIG["project_name"],
        JHEAD_CONFIG["project_dir"],
        JHEAD_CONFIG["binary_name"],
        JHEAD_CONFIG["build_cmd"],
        JHEAD_CONFIG["clean_cmd"],
        JHEAD_CONFIG["input_args"],
        work_dir
    )
    runner.run()

if __name__ == "__main__":
    main()
