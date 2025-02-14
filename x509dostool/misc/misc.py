#!/usr/bin/env python3

import os
import re
import sys
import time
import json
import base64
import subprocess

from Crypto.Util.number import *
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc5280, rfc5480

def load_config(json_file):
    #json_file = os.path.join(os.path.dirname(__file__), json_file)

    if not os.path.exists(json_file):
        alert(f"the specified path '{json_file}' does not exist.")

    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except:
        alert(f"json parsing error, invalid config file.")

    return config

def red(s):
    return "\033[31m" + s + "\033[0m"

def green(s):
    return "\033[32m" + s + "\033[0m"

def blue(s):
    return "\033[34m" + s + "\033[0m"

def prompt(info, color_func = None):
    if color_func is None:
        print(f"[+] {info}")
    else:
        print(color_func(f"[+] {info}"))

def alert(info, color_func = None):
    if color_func is None:
        print(f"[!] error: {info}\n[x] exited.")
    else:
        print(color_func(f"[!] error: {info}\n[x] exited."))

    sys.exit(1)

def make_divider(c, num):
    print(c * num)

def is_hex_string(s):
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))

def expr_to_int(expr):
    try:
        res = int(eval(str(expr)))
    except Exception as e:
        alert(f"{e}: {expr}")
    
    if res < 0:
        alert("the specified number cannot be negative.")

    return res

def expr_to_hex(expr):
    res = hex(expr_to_int(expr))[2:]

    if len(res) % 2 == 1:
        res = '0' + res

    return res

def bytes_to_bin(data):
    try:
        return ''.join(f'{byte:08b}' for byte in data)
    except KeyboardInterrupt:
        print("")
        sys.exit(1)

def bytes_to_point(data, ret_tag = False):
    tag = bytes([data[0]])
    data = data[1:]

    if tag == b'\x02' or tag == b'\x03':
        x = data
        point = [x, None]

    elif tag == b'\x04':
        if len(data) % 2 != 0:
            alert("invalid data to be converted into a curve point for tag 04.")

        x = data[: len(data) // 2]
        y = data[len(data) // 2: ]
        point = [x, y]
    
    else:
        alert("invalid prefix of curve point, only 02/03/04 are supported.")
    
    if ret_tag:
        return [tag, point]
    else:
        return point

def der_to_pem(prefix, suffix, der):
    pem = prefix
    b64_data = base64.b64encode(der).decode()

    for i in range(0, len(b64_data), 64):
        pem += b64_data[i: i + 64] + '\n'

    pem += suffix
    return pem

def pem_to_der(pem):
    lines = pem.strip().splitlines()
    b64_data = ''.join(lines[1:-1])

    der = base64.b64decode(b64_data)
    return der

def bytes_padding(data, padding_len):
    try:
        return b'\x00' * (padding_len - len(data)) + data
    except KeyboardInterrupt:
        print("")
        sys.exit(1)

def read_cert_data(in_path, ret_pem = False):
    if not os.path.exists(in_path):
        alert(f"the specified file '{in_path}' does not exist.")
    
    with open(in_path, "rb") as file:
        cert_data = file.read()
    
    pem = False
    if cert_data.startswith(b"-----BEGIN CERTIFICATE-----\n") and cert_data.endswith(b"-----END CERTIFICATE-----\n"):
        cert_data = pem_to_der(cert_data.decode())
        pem = True
    
    if ret_pem:
        return cert_data, pem
    else:
        return cert_data

def write_cert_data(cert_data, out_path, pem = False):
    if pem == True:
        cert_data = der_to_pem("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n", cert_data).encode()

    _ = open(out_path, "wb").write(cert_data)

def read_cert(in_path):
    cert_data = read_cert_data(in_path)

    try:
        cert, _ = decoder.decode(cert_data, asn1Spec=rfc5280.Certificate())
    except:
        alert(f"the specified file is not a valid X.509 certificate.")
    
    return cert

def write_cert(cert, out_path, pem = False):
    try:
        cert_data = encoder.encode(cert)
    
    except KeyboardInterrupt:
        print("")
        sys.exit(1)
    
    except Exception as e:
        text = str(e)

        remove = lambda text: remove(re.sub(r'<[^<>]*>', '', text)) if re.search(r'<[^<>]*>', text) else text
        alert(remove(text[text.rfind("Error encoding"):]))

    write_cert_data(cert_data, out_path, pem)

def find_parent_lines(lines, target_line):
    parent_lines = []
    stack = []
    for line in lines:
        depth = int(line.split('d=')[1].split(' ')[0])

        while stack and stack[-1][0] >= depth:
            stack.pop()

        stack.append((depth, line))

        if target_line in line:
            parent_lines = [x[1] for x in stack]
            break

    return parent_lines

def make_lines(cert_name, nl = False, pem = False):
    cmd = "set -e;"

    if pem:
        cmd += f"openssl asn1parse -in {cert_name}"
    else:
        cmd += f"openssl asn1parse -inform der -in {cert_name}"
    
    if nl:
        cmd += " | nl"

    res = run_cmd(cmd)
    output = res.stdout

    if 'Error' in output:
        lines = output.split('\n')[:-2]
    else:
        lines = output.split('\n')[:-1]

    return lines

def extract_length_field_positions(lines, pattern = r'(\d+):d=\d+\s+hl=(\d+)'):
    positions = []
    for line in lines:
        matches = re.findall(pattern, line)

        if matches:
            start = int(matches[0][0])
            hl = int(matches[0][1])
            positions += [(start, hl)]
        else:
            alert("match failed.")

    return positions[::-1]

def encode_length(length):
    if length < 128:
        return bytes([length])
    else:
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, byteorder='big')

        return bytes([0x80 | len(length_bytes)]) + length_bytes

def decode_length(data):
    if data[0] < 128:
        return data[0]
    else:
        length = 0

        for i in range(1, (data[0] & 0x7f) + 1):
            length = (length << 8) | data[i]
            
        return length

def adjust_length(data, positions, offset):
    data = bytearray(data)

    for start, hl in positions:
        new = encode_length(
                    decode_length(
                        data[start + 1: start + hl]
                    ) + offset
                )

        data[start + 1: start + hl] = new
        offset += len(new) - len(data[start + 1: start + hl])

    return bytes(data)

def run_cmd(cmd, capture_output = True, text = True, env = None, check = True, errors = None, exit = True):
    try:
        res = subprocess.run(["bash", "-c", cmd], capture_output = capture_output, text = text, env = env, check = check, errors = errors)
    except Exception as e:
        alert(f"{e}")

    if res.returncode == 0 and res.stderr == '':
        return res

    else:
        if exit:
            alert(f"command execution error: {res.stderr}".strip())
        else:
            return res

def exec_shell_script_with_cert(script_path, cert_path):
    process = subprocess.Popen(["/bin/bash", script_path, cert_path], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    return process

def get_all_filenames(path, suffixes = None):
    if not os.path.exists(path):
        alert(f"the specified path '{path}' does not exist.")

    if os.path.isfile(path):
        return [path] if (suffixes is None or any(path.endswith(suffix) for suffix in suffixes)) else []

    elif os.path.isdir(path):
        entries = os.listdir(path)
        filenames = [
            os.path.join(path, entry)
            for entry in entries
            if os.path.isfile(os.path.join(path, entry)) and (suffixes is None or any(entry.endswith(suffix) for suffix in suffixes))
        ]

        filenames = sorted(filenames)
        return filenames

    else:
        alert(f"the specified path '{path}' is invalid.")

def change_suffix(filename, suffix = ".pub"):
    if '.' in filename:
        filename = filename.rsplit('.', 1)[0] + suffix
    else:
        filename += suffix
    return filename