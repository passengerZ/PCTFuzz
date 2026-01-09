#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess
import time
import threading
from pathlib import Path
from multiprocessing import Pool

afl_fuzz       = "/home/aaa/FPCT/AFLplusplus/afl-fuzz"
afl_compiler   = "/home/aaa/FPCT/AFLplusplus/afl-clang-lto"

symcc_compiler = "/home/aaa/FPCT/symcc/build/symcc"
hybridfuzzer_bin  = "/home/aaa/FPCT/symcc/build/hybrid/HybridFuzzer"

class SymccAFLpp:
    def __init__(self, project_name, project_dir, binary_name, build_cmd, clean_cmd, input_args, work_dir, time_out):
        self.project_name = project_name
        self.project_dir  = project_dir
        self.binary_name  = binary_name
        self.build_cmd    = build_cmd
        self.clean_cmd    = clean_cmd
        self.input_args   = input_args
        self.time_out     = time_out

        self.work_dir   = work_dir
        self.input_dir  = Path(os.path.join(work_dir, "fuzz_in"))
        self.output_dir = Path(os.path.join(work_dir, "fuzz_out"))
        self.binary_dir = Path(os.path.join(work_dir, "symcc_bin"))

        self.src_bin   = Path(os.path.join(self.project_dir, binary_name))
        self.afl_bin   = Path(os.path.join(self.binary_dir, binary_name+"_afl"))
        self.symcc_bin = Path(os.path.join(self.binary_dir, binary_name+"_symcc"))

        self.afl_proc   = None
        self.symcc_proc = None

        self._validate()

    def _validate(self):
        if not Path(self.project_dir).exists():
            raise FileNotFoundError(f"Source directory not found: {self.project_dir}")
        if not Path(hybridfuzzer_bin).exists():
            raise FileNotFoundError(f"HybridFuzzer binary not found: {hybridfuzzer_bin}")
        if not Path(symcc_compiler).exists():
            raise FileNotFoundError(f"SymCC compiler not found: {symcc_compiler}")

    def prepare_dirs(self):
        print("[*] Preparing directories...")
        for d in [self.input_dir, self.output_dir, self.binary_dir]:
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
            "CC": afl_compiler,
        })

        self.run_shell_cmd(self.clean_cmd, self.project_dir, env)
        self.run_shell_cmd(self.build_cmd, self.project_dir, env)

        if not self.src_bin.exists():
            raise FileNotFoundError(f"Binary not found after build: {self.src_bin}")
        shutil.copy(self.src_bin, self.afl_bin)
        print(f"[+] AFL binary: {self.afl_bin}")

    def compile_symcc_binary(self):
        print("[*] Compiling SymCC binary...")
        env = os.environ.copy()
        env.update({
            "CC":  symcc_compiler
        })

        self.run_shell_cmd(self.clean_cmd, self.project_dir, env)
        self.run_shell_cmd(self.build_cmd, self.project_dir, env)

        if not self.src_bin.exists():
            raise FileNotFoundError(f"SymCC binary not found: {self.src_bin}")
        shutil.copy(self.src_bin, self.symcc_bin)
        print(f"[+] SymCC binary: {self.symcc_bin}")

    def start_afl(self):
        print("[*] Starting AFL++ master...")
        env = os.environ.copy()
        env.update({
            "AFL_NO_UI": "1",
            #"AFL_NO_AFFINITY": "1",
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
            "AFL_SKIP_CRASHES": "1",
            "AFL_NO_FASTRESUME": "1",
            "AFL_AUTORESUME" : "1",
            "AFL_SYNC_TIME"  : "10",
        })

        cmd = [
            afl_fuzz,
            "-M", "afl-master",
            "-i", str(self.input_dir),
            "-o", str(self.output_dir),
            "--", str(self.afl_bin)
        ]
        cmd.extend(self.input_args)

        self.afl_proc = subprocess.Popen(
            cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
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

    def start_symcc(self):
        print("[*] Starting SymccAFLpp...")
        env = os.environ.copy()

        afl_master_dir = self.output_dir / "afl-master"
        for _ in range(10):
            if afl_master_dir.exists():
                break
            time.sleep(1)
        else:
            raise RuntimeError("AFL master dir not created in 10s")

        cmd = [
            hybridfuzzer_bin,
            "--fuzzer-name=afl-master",
            f"--output-dir={self.output_dir}",
            str(self.symcc_bin)
        ]

        self.symcc_proc = subprocess.Popen(
            cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"[+] Symcc started (PID: {self.symcc_proc.pid})")
        
    def stop(self):
        print("[*] Shutting down...")
        for name, proc in [("AFL++", self.afl_proc), ("HybridFuzzer", self.symcc_proc)]:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except:
                    proc.kill()
        print("[+] Done.")

    def run(self):
        print(f"[+] Starting SymccAFLpp for project: {self.project_name}")
        print("[+] Hybrid fuzzing running!")
        print(f"   Project: {self.project_name}")
        print(f"   AFL Output: {self.output_dir}/afl-master")
        print( "   Press Ctrl+C to stop...\n")

        self.prepare_dirs()
        self.compile_afl_binary()
        self.compile_symcc_binary()

        start_time = time.time()
        self.start_afl()
        time.sleep(5)
        self.start_symcc()

        try:
            while True:
                elapsed = time.time() - start_time
                if elapsed >= self.time_out:
                    print(f"[!] Time limit reached ({self.time_out} seconds). Stopping...")
                    break

                if self.symcc_proc.poll() is not None and self.afl_proc.poll() is not None:
                    print("[!] Both processes exited.")
                    break
                    
                time.sleep(3)
        except KeyboardInterrupt:
            print("\n[!] Interrupt received.")
        finally:
            self.stop()

JHEAD_CONFIG = {
    "project_name": "jhead-3.08",
    "project_dir" : "/home/aaa/FPCT/bench/jhead-3.08",
    "build_cmd": ["make"],
    "clean_cmd": ["make", "clean"],
    "binary_name": "jhead",
    "input_args": ["@@"],
}
    
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
    
    runner = SymccAFLpp(
        project_name,
        private_src,
        binary_name,
        build_cmd,
        clean_cmd,
        input_args,
        work_dir,
        time_out,
    )
    runner.run()

def main():
    BASE_DIR   = "/home/aaa/FPCT/multi_run"
    TOOL_NAME  = "SymccAFLpp"
    CONFIG_MAP = JHEAD_CONFIG
    TIME_OUT   = 120

    num_runs = 2

    args_list = [
        (BASE_DIR, TOOL_NAME, i, CONFIG_MAP, TIME_OUT)
        for i in range(1, num_runs + 1)
    ]

    with Pool(processes=num_runs) as pool:
        try:
            pool.starmap(run_single_work, args_list)
        except KeyboardInterrupt:
            print("\n[!] Received Ctrl+C, terminating workers...")
            pool.terminate()
            pool.join()
        else:
            pool.close()
            pool.join()

    print(f"[+] All {num_runs} runs completed.")

if __name__ == "__main__":
    main()
