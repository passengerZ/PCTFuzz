#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess
import time
import signal
import threading
from pathlib import Path

# ================== Configuration (adjust as needed) ==================
TARGET_SRC = "symcc_test"          # Source filename (without .c)
INPUT_DIR = "./fuzz_in"
OUTPUT_DIR = "./fuzz_out"
CORPUS_DIR = "./corpus"            # Initial seed corpus directory

# PCTFuzzer binary path (ensure this is correct)
PCTFUZZER_BIN = "/home/aaa/FPCT/PCTFuzz/cmake-build-debug/transform/PCTFuzzer"
PCT_EVALUATOR = "/home/aaa/FPCT/test/pct-evaluator.so"

# Environment variables (matches your shell script)
ENV_VARS = {
    "CC": "afl-clang-lto",
    "CXX": "afl-clang-lto++",
    "AFL_NO_UI": "1",
    "AFL_NO_AFFINITY": "1",
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
    "AFL_SKIP_CRASHES": "1",
    "AFL_NO_FASTRESUME" : "1",
    "PCT_CFG_PATH": f"/home/aaa/FPCT/test/{TARGET_SRC}.cfg",
}

# AFL and SymCC binary names
AFL_BINARY = "./afl_bin"
SYMCC_BINARY = "./symcc_bin"

# AFL master instance name (must match --fuzzer-name used by PCTFuzzer)
AFL_MASTER_NAME = "afl-master"
# ======================================================================


class PCTFuzzRunner:
    def __init__(self):
        self.afl_proc = None
        self.pct_proc = None
        self.pct_stderr_thread = None

        # Path objects
        self.target_src = Path(f"{TARGET_SRC}.c")
        self.input_dir  = Path(INPUT_DIR)
        self.output_dir = Path(OUTPUT_DIR)
        self.corpus_dir = Path(CORPUS_DIR)
        self.afl_bin    = Path(AFL_BINARY)
        self.symcc_bin  = Path(SYMCC_BINARY)
        
        self._validate()

    def _validate(self):
        if not self.target_src.exists():
            raise FileNotFoundError(f"Source file not found: {self.target_src}")
        if not self.corpus_dir.exists() or not any(self.corpus_dir.iterdir()):
            raise FileNotFoundError(f"Corpus directory is empty or does not exist: {self.corpus_dir}")
        if not Path(PCTFUZZER_BIN).exists():
            raise FileNotFoundError(f"PCTFuzzer binary not found: {PCTFUZZER_BIN}")

    def prepare_dirs(self):
        print("[*] Cleaning and preparing directories...")
        for d in [self.input_dir, self.output_dir]:
            if d.exists():
                shutil.rmtree(d)
            d.mkdir(exist_ok=True)

        # Copy seed files
        seeds = list(self.corpus_dir.glob("*"))
        for seed in seeds:
            if seed.is_file():
                shutil.copy(seed, self.input_dir / seed.name)
        print(f"[+] Copied {len(seeds)} seed(s) to {self.input_dir}")

    def compile_afl_binary(self):
        print("[*] Compiling AFL++ binary...")
        env = os.environ.copy()
        env.update(ENV_VARS)

        cmd = ["afl-clang-lto", str(self.target_src), "-o", str(self.afl_bin)]
        subprocess.run(cmd, env=env, check=True)
        print(f"[+] AFL binary generated: {self.afl_bin}")
        
    def compile_evaluator_library(self):
        print("[*] Compiling PCT Evaluator library...")
        env = os.environ.copy()
        env.update(ENV_VARS)

        cmd = ["gcc", "-O3", "-funroll-loops", "-g", "-shared", "-fPIC", self.pct_evaluator_src, "-o", str(PCT_EVALUATOR)]
        subprocess.run(cmd, env=env, check=True)
        print(f"[+] PCT Evaluator generated: {PCT_EVALUATOR}")

    def compile_symcc_binary(self):
        print("[*] Compiling SymCC binary...")
        env = os.environ.copy()
        env.update(ENV_VARS)
        
        symcc_compiler = "/home/aaa/FPCT/PCTFuzz/cmake-build-debug/symcc"
        if not Path(symcc_compiler).exists():
            raise FileNotFoundError(f"SymCC compiler not found: {symcc_compiler}")

        cmd = [symcc_compiler, str(self.target_src), "-o", str(self.symcc_bin)]
        subprocess.run(cmd, env=env, check=True)
        print(f"[+] SymCC binary generated: {self.symcc_bin}")

    def start_afl(self):
        print("[*] Starting AFL++ master instance...")
        env = os.environ.copy()
        env.update(ENV_VARS)
        cmd = [
            "afl-fuzz",
            "-M", AFL_MASTER_NAME,
            "-i", "./" + str(self.input_dir),
            "-o", "./" + str(self.output_dir),
            "--", "./" + str(self.afl_bin), "@@"
        ]

        self.afl_proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"[+] AFL++ started (PID: {self.afl_proc.pid})")
        
    def restart_afl(self):
        """Pause AFL++ for 2 seconds then restart it."""
        print("[*] Pausing AFL++...")
    
        # Terminate current AFL process
        if self.afl_proc and self.afl_proc.poll() is None:
            self.afl_proc.terminate()
            try:
                self.afl_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("  - AFL++ did not terminate gracefully, killing...")
                self.afl_proc.kill()
                self.afl_proc.wait()
        time.sleep(1)
    
        print("[+] Restarting AFL++...")
        # Use resume mode: -i -
        cmd = [
            "afl-fuzz",
            "-M", AFL_MASTER_NAME,
            "-i", "-",
            "-o", "./" + str(self.output_dir),
            "--", "./" + str(self.afl_bin), "@@"
        ]
        
        env = os.environ.copy()
        env.update(ENV_VARS)
        env["AFL_PCT_EVALUATOR_LIBRARY"] = PCT_EVALUATOR
        
        self.afl_proc = subprocess.Popen(
            cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print(f"[+] AFL++ restarted (PID: {self.afl_proc.pid})")

    def start_pctfuzzer(self):
        print("[*] Starting PCTFuzzer...")
        env = os.environ.copy()
        env.update(ENV_VARS)
    
        # Wait for AFL to create the master instance directory
        afl_master_dir = self.output_dir / AFL_MASTER_NAME
        for _ in range(10):
            if afl_master_dir.exists():
                break
            time.sleep(1)
        else:
            raise RuntimeError("AFL master directory was not created within 10 seconds")

        cmd = [
            PCTFUZZER_BIN,
            f"--fuzzer-name={AFL_MASTER_NAME}",
            f"--output-dir=./{self.output_dir}",
            "./" + str(self.symcc_bin)
        ]

        # Capture stderr for monitoring
        self.pct_proc = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,   # invisible
            stderr=subprocess.PIPE,      # Capture output
            universal_newlines=False     # We'll decode manually
        )
        print(f"[+] PCTFuzzer started (PID: {self.pct_proc.pid})")

        # Start stderr monitoring thread
        self.pct_stderr_thread = threading.Thread(target=self.monitor_pct_stderr, daemon=True)
        self.pct_stderr_thread.start()
        
    def monitor_pct_stderr(self):
        """Background thread to monitor PCTFuzzer stderr."""
        try:
            while self.pct_proc.poll() is None:
                line = self.pct_proc.stderr.readline()
                if not line:
                    break
                line_str = line.decode('utf-8', errors='replace').strip()
                print(f"{line_str}")
            
                # Check for trigger string
                if "create new pct-evaluator" in line_str:
                    print(f"[!] PCT has generated new evaluator, Pausing AFL++...")
                    
                    # rebuild the pct-evaluator
                    self.pct_evaluator_src = line_str.split(':')[1].strip()
                    self.compile_evaluator_library()
                    
                    self.restart_afl()
                    
        except Exception as e:
            print(f"[ERROR] Error monitoring PCTFuzzer stderr: {e}")
        finally:
            # Drain remaining stderr
            for line in iter(self.pct_proc.stderr.readline, b''):
                print(f"{line.decode('utf-8', errors='replace').strip()}")

    def run(self):
        print("[+] Starting PCTFuzz hybrid fuzzing...\n")
        
        env = os.environ.copy()
        env.update(ENV_VARS)
        cfg_path = Path(ENV_VARS["PCT_CFG_PATH"])

        self.prepare_dirs()
        self.compile_afl_binary()
        self.compile_symcc_binary()

        self.start_afl()
        time.sleep(10)  # Ensure AFL has initialized

        self.start_pctfuzzer()

        print("\n[+] Hybrid fuzzing is running!")
        print(f"   - AFL output directory: {self.output_dir}/{AFL_MASTER_NAME}")
        print(f"   - PCTFuzzer is monitoring this directory and generating new inputs")
        print("\nPress Ctrl+C to stop...\n")

        try:
            while True:
                if self.pct_proc.poll() is None or self.afl_proc.poll() is None:
                    time.sleep(1)  # 更短的 sleep，更快响应
                else:
                    print("[!] PCTFuzzer/AFL++ process exited.")
                    break
                
        except KeyboardInterrupt:
            print("\n[!] Received interrupt signal, shutting down...")
        finally:
            self.stop()

    def stop(self):
        print("[*] Terminating child processes...")

        for name, proc in [("AFL++", self.afl_proc), ("PCTFuzzer", self.pct_proc)]:
            if proc and proc.poll() is None:
                print(f"  - Terminating {name} (PID {proc.pid})...")
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print(f"  - Killing {name} forcefully...")
                    proc.kill()

        print("[+] All processes stopped.")


def main():
    runner = PCTFuzzRunner()
    runner.run()


if __name__ == "__main__":
    main()
