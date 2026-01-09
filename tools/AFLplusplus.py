#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess
import time
import threading
from pathlib import Path
from multiprocessing import Pool

afl_compiler = "/home/aaa/FPCT/AFLplusplus/afl-clang-lto"
afl_fuzz     = "/home/aaa/FPCT/AFLplusplus/afl-fuzz"

class AFLplusplus:
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
        self.binary_dir = Path(os.path.join(work_dir, "afl_bin"))

        self.src_bin   = Path(os.path.join(self.project_dir, binary_name))
        self.afl_bin   = Path(os.path.join(self.binary_dir, binary_name+"_afl"))
        
        self.afl_proc = None

        self._validate()

    def _validate(self):
        if not Path(self.project_dir).exists():
            raise FileNotFoundError(f"Source directory not found: {self.project_dir}")

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
        
    def stop(self):
        print("[*] Shutting down...")
        for name, proc in [("AFL++", self.afl_proc)]:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except:
                    proc.kill()
        print("[+] Done.")

    def run(self):
        print(f"[+] Starting AFLplusplus for project: {self.project_name}")
        print("[+] AFLplusplus running!")
        print(f"   Project: {self.project_name}")
        print(f"   AFLplusplus Output: {self.output_dir}/afl-master")
        print( "   Press Ctrl+C to stop...\n")

        self.prepare_dirs()
        self.compile_afl_binary()

        start_time = time.time()
        self.start_afl()

        try:
            while True:
                elapsed = time.time() - start_time
                if elapsed >= self.time_out:
                    print(f"[!] Time limit reached ({self.time_out} seconds). Stopping...")
                    break

                if self.afl_proc.poll() is not None:
                    print("[!] AFL++ processes exited.")
                    break
                    
                time.sleep(3)
        except KeyboardInterrupt:
            print("\n[!] Interrupt received.")
        finally:
            self.stop()
