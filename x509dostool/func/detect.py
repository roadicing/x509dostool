#!/usr/bin/env python3

import time
import psutil
import threading

from ..misc.misc import *

def monitor_cpu(ps_process, cpu_rounds, cpu_threshold, result):
    cpu_usage_sum = 0
    for _ in range(cpu_rounds):
        try:
            cpu_usage = ps_process.cpu_percent(interval=1)
        except Exception as e:
            break

        cpu_usage_sum += cpu_usage
        time.sleep(1)
    
    cpu_usage_avg_percent = (cpu_usage_sum / cpu_rounds) / 100
    result["cpu"] = cpu_usage_avg_percent >= cpu_threshold

def monitor_memory(ps_process, mem_rounds, mem_threshold, result):
    mem_usage_list = [0]
    for cnt in range(mem_rounds):
        try:
            mem_usage = ps_process.memory_percent()
        except:
            break
        
        if mem_usage > mem_usage_list[-1]:
            mem_usage_list += [mem_usage]
        else:
            break

        time.sleep(1)
    
    if len(mem_usage_list) > 1:
        mem_usage_inc_percent = ((mem_usage_list[-1] - mem_usage_list[1]) / mem_usage_list[1])
        result["memory"] = mem_usage_inc_percent >= mem_threshold

def monitor_process(process, cpu_rounds, mem_rounds, cpu_threshold, mem_threshold):
    issue_num = 0

    try:
        time.sleep(4)

        pid = int(subprocess.check_output(["pgrep", "-P", str(process.pid)]).decode().strip())
        ps_process = psutil.Process(pid)

        time.sleep(1)

        result = {"cpu": False, "memory": False}

        cpu_thread = threading.Thread(target=monitor_cpu, args=(ps_process, cpu_rounds, cpu_threshold, result))
        mem_thread = threading.Thread(target=monitor_memory, args=(ps_process, mem_rounds, mem_threshold, result))

        cpu_thread.start()
        mem_thread.start()

        cpu_thread.join()
        mem_thread.join()

        if result["cpu"]:
            prompt("cpu exhaustion detected!", color_func = red)
            issue_num += 1
        else:
            prompt("no cpu exhaustion detected.", color_func = green)

        if result["memory"]:
            prompt("memory exhaustion detected!", color_func = red)
            issue_num += 1
        else:
            prompt("no memory exhaustion detected.", color_func = green)

        prompt("no crash detected.", color_func = green)

        if psutil.pid_exists(ps_process.pid):
            ps_process.kill()
    
    except KeyboardInterrupt:
        print("")
        sys.exit(1)

    except (subprocess.CalledProcessError, psutil.NoSuchProcess):
        try:
            out, err = process.communicate(timeout = 10)
        except subprocess.TimeoutExpired:
            alert("the timeout occurred during the detection, please try re-running it to test.")

        if process.returncode == 0 and err == b'':
            prompt("no cpu exhaustion detected.", color_func = green)
            prompt("no memory exhaustion detected.", color_func = green)
            prompt("no crash detected.", color_func = green)

        else:
            if (b"segmentation fault" in err.lower()) or (b"aborted" in err.lower()):
                # skip the errors of crypto++
                if b"berdecodeerr" not in err.lower():
                    prompt("no cpu exhaustion detected.", color_func = green)
                    prompt("no memory exhaustion detected.", color_func = green)
                    prompt("crash detected!", color_func = red)
                    issue_num += 1
                
                else:
                    prompt("script error found (or potential mitigation strategy from the library), manual confirmation required.")
                    prompt(f"error info: {err}")

            else:
                prompt("script error found (or potential mitigation strategy from the library), manual confirmation required.")
                prompt(f"error info: {err}")

    except:
        try:
            out, err = process.communicate(timeout = 10)
        except subprocess.TimeoutExpired:
            alert("the timeout occurred during the detection, please try re-running it to test.")

        alert(err)
    
    return issue_num

def run_detect(script_path, cert_path, cpu_rounds, mem_rounds, cpu_threshold, mem_threshold):
    prompt("detecting...")

    process = exec_shell_script_with_cert(script_path, cert_path)
    issue_num = monitor_process(process, cpu_rounds, mem_rounds, cpu_threshold, mem_threshold)

    process.kill()

    return issue_num

def handle_detects(script_path, cert_path, cpu_rounds, mem_rounds, cpu_threshold, mem_threshold):
    script_paths = get_all_filenames(script_path, suffixes = [".sh"])
    cert_paths = get_all_filenames(cert_path)

    test_num = 0
    postive_test_num = 0
    for cnt, script_path in enumerate(script_paths):
        make_divider("=", 80)
        prompt(f"currently detected library: [{script_path}]")

        for cert_path in cert_paths:
            make_divider("-", 80)
            
            prompt(f"currently used certificate: [{cert_path}]")
            test_num += 1
            postive_test_num += (run_detect(script_path, cert_path, cpu_rounds, mem_rounds, cpu_threshold, mem_threshold) > 0)
        
        make_divider("-", 80)
        prompt(f"the detection for [{script_path}] is complete.")

        # make_divider("=", 80)
        
        if cnt != len(script_paths) - 1:
            print("")
    
    prompt(f"results: performed {test_num} tests, and issues were detected in {postive_test_num} of them.")