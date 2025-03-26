#!/usr/bin/env python3

import math
from Crypto.Util.number import *

from pyasn1.type.univ import *
from pyasn1.type.char import UTF8String
from pyasn1.type.useful import UTCTime

from ..misc.misc import *
from ..ext_pyasn1_modules.ecdsa_pyasn1_modules import *

def set_rsa_public_key(spki, e = None, n = None):
    pub = spki['subjectPublicKey']

    try:
        pub, _ = decoder.decode(pub.asOctets(), asn1Spec = rfc5480.RSAPublicKey())
    except:
        alert("the input does not contain a valid RSA public key.")

    if e is not None:
        pub['publicExponent'] = expr_to_int(e)

    if n is not None:
        pub['modulus'] = expr_to_int(n)

    bit_string_pub = bytes_to_bin(encoder.encode(pub))
    spki['subjectPublicKey'] = BitString(bit_string_pub)

def set_dsa_public_key(spki, pub = None, p = None, q = None, g = None):
    params = spki['algorithm']['parameters']

    try:
        params, _ = decoder.decode(params.asOctets(), asn1Spec = rfc5480.DSS_Parms())
    except:
        alert("the input does not contain a valid DSA public key.")

    if p is not None:
        params['p'] = expr_to_int(p)

    if q is not None:
        params['q'] = expr_to_int(q)

    if g is not None:
        params['g'] = expr_to_int(g)

    spki['algorithm']['parameters'] = Any(encoder.encode(params))

    if pub is not None:
        pub = expr_to_int(pub)

        bit_string_pub = bytes_to_bin(encoder.encode(Integer(pub)))
        spki['subjectPublicKey'] = BitString(bit_string_pub)

def set_ecdsa_public_key(spki, curve_name_oid = None, P_hex = None, compressed = False):
    params = spki['algorithm']['parameters']

    try:
        params, _ = decoder.decode(params.asOctets(), asn1Spec = rfc5480.ECParameters())
    except:
        alert("the input does not contain a valid ECDSA public key (named curve).")

    if curve_name_oid is not None:
        try:
            params['namedCurve'] = ObjectIdentifier(tuple([int(x) for x in curve_name_oid.split('.')]))
        except Exception as e:
            alert(f"{e}")

        spki['algorithm']['parameters'] = Any(encoder.encode(params))
    
    if P_hex is not None:
        if not is_hex_string(P_hex):
            alert("the input public key point must be a hex string.")

        if len(P_hex) % 2 == 1:
            alert("to avoid ambiguity, the length of the input hex string must be even.")

        if P_hex[:2] not in ['02', '03', '04']:
            alert("invalid prefix of public key point, only 02/03/04 are supported.")

        spki['subjectPublicKey'] = BitString(bytes_to_bin(long_to_bytes(int(P_hex, 16))))
    
    tag, P = bytes_to_point(spki['subjectPublicKey'].asOctets(), ret_tag = True)

    if compressed:
        if tag == b'\x04':
            tag = b'\x03' if P[1][-1] % 2 == 1 else b'\x02'
            spki['subjectPublicKey'] = BitString(bytes_to_bin(tag + P[0]))

def set_ecdsa_public_key_explicitly(spki, type = "fp", P_hex = None, p = None, degree = None, t3 = None, t2 = None, t1 = None, a = None, b = None, G_hex = None, order = None, cofactor = None, seed = None, balanced = False, compressed = False):
    params = spki['algorithm']['parameters']
    seed_flag = False

    if type == "fp":
        try:
            params, _ = decoder.decode(params.asOctets(), asn1Spec = PrimeField())
        except:

            try:
                params, _ = decoder.decode(params.asOctets(), asn1Spec = PrimeFieldWithSeed())
                seed_flag = True
            except:
                alert("the input does not contain a valid ECDSA public key (explicit, F_p).")

        if p is not None:
            p = expr_to_int(p)

            params['field-id']['prime'] = p
        
        if balanced == True:
            padding_len = math.ceil((int(params['field-id']['prime']).bit_length() + 7) // 8)

        else:
            padding_len = 0

    elif type == "f2m_tp":
        try:
            params, _ = decoder.decode(params.asOctets(), asn1Spec = TrinomialBinaryField())
        except:

            try:
                params, _ = decoder.decode(params.asOctets(), asn1Spec = TrinomialBinaryFieldWithSeed())
                seed_flag = True
            except:
                alert("the input does not contain a valid ECDSA public key (explicit, F_{2^m}, trinomial).")

        if degree is not None:
            degree = expr_to_int(degree)

            params['field-id']['poly']['degree'] = degree

        if t3 is not None:
            t3 = expr_to_int(t3)
            
            params['field-id']['poly']['t'] = t3

        if balanced == True:
            padding_len = math.ceil((int(params['field-id']['poly']['degree']) + 7) // 8)

        else:
            padding_len = 0

    elif type == "f2m_pp":
        try:
            params, _ = decoder.decode(params.asOctets(), asn1Spec = PentanomialBinaryField())
        except:

            try:
                params, _ = decoder.decode(params.asOctets(), asn1Spec = PentanomialBinaryFieldWithSeed())
                seed_flag = True
            except:
                alert("the input does not contain a valid ECDSA public key (explicit, F_{2^m}, pentanomial).")

        if degree is not None:
            degree = expr_to_int(degree)

            params['field-id']['poly']['degree'] = degree

        if t1 is not None:
            t1 = expr_to_int(t1)
            
            params['field-id']['poly']['ts']['t_0'] = t1
        
        if t2 is not None:
            t2 = expr_to_int(t2)

            params['field-id']['poly']['ts']['t_1'] = t2
        
        if t3 is not None:
            t3 = expr_to_int(t3)

            params['field-id']['poly']['ts']['t_2'] = t3

        if balanced == True:
            padding_len = math.ceil((int(params['field-id']['poly']['degree']) + 7) // 8)
        else:
            padding_len = 0


    if a is not None:
        a_hex = expr_to_hex(a)
    else:
        a_hex = params['curve']['a'].asOctets().hex()

    #params['curve']['a'] = OctetString(bytes.fromhex(a_hex))
    bytes_a = bytes_padding(bytes.fromhex(a_hex), padding_len)
    params['curve']['a'] = OctetString(bytes_a)

    if b is not None:
        b_hex = expr_to_hex(b)
    else:
        b_hex = params['curve']['b'].asOctets().hex()

    #params['curve']['b'] = OctetString(bytes.fromhex(b_hex))
    bytes_b = bytes_padding(bytes.fromhex(b_hex), padding_len)
    params['curve']['b'] = OctetString(bytes_b)

    if G_hex is not None:
        if not is_hex_string(G_hex):
            alert("the input base point must be a hex string.")

        if len(G_hex) % 2 == 1:
            alert("to avoid ambiguity, the length of the input hex string must be even.")

        if G_hex[:2] not in ['02', '03', '04']:
            alert("invalid prefix of base point, only 02/03/04 are supported.")

        params['base'] = OctetString(long_to_bytes(int(G_hex, 16)))

    if compressed:
        tag, G = bytes_to_point(params['base'].asOctets(), ret_tag = True)

        if tag == b'\x04':
            tag = b'\x03' if G[1][-1] % 2 == 1 else b'\x02'
            params['base'] = OctetString(tag + G[0])

    if balanced:
        tag, G = bytes_to_point(params['base'].asOctets(), ret_tag = True)
        res = tag

        if G[0] is not None:
            G[0] = bytes_padding(G[0], padding_len)
            res += G[0]

        if G[1] is not None:
            G[1] = bytes_padding(G[1], padding_len)
            res += G[1]
        
        params['base'] = OctetString(res)


    if order is not None:
        order = expr_to_int(order)

        params['order'] = order


    if cofactor is not None:
        cofactor = expr_to_int(cofactor)

        params['cofactor'] = cofactor


    if seed is not None and seed_flag:
        seed_hex = expr_to_hex(seed)

        bit_string_seed = bytes_to_bin(bytes.fromhex(seed_hex))
        params['curve']['seed'] = BitString(bit_string_seed)

    spki['algorithm']['parameters'] = Any(encoder.encode(params))


    if P_hex is not None:
        if not is_hex_string(P_hex):
            alert("the input public key point must be a hex string.")

        if len(P_hex) % 2 == 1:
            alert("to avoid ambiguity, the length of the input hex string must be even.")

        if P_hex[:2] not in ['02', '03', '04']:
            alert("invalid prefix of public key point, only 02/03/04 are supported.")

        spki['subjectPublicKey'] = BitString(bytes_to_bin(long_to_bytes(int(P_hex, 16))))

    if compressed:
        tag, P = bytes_to_point(spki['subjectPublicKey'].asOctets(), ret_tag = True)

        if tag == b'\x04':
            tag = b'\x03' if P[1][-1] % 2 == 1 else b'\x02'
            spki['subjectPublicKey'] = BitString(bytes_to_bin(tag + P[0]))

    if balanced:
        tag, P = bytes_to_point(spki['subjectPublicKey'].asOctets(), ret_tag = True)
        res = tag

        if P[0] is not None:
            P[0] = bytes_padding(P[0], padding_len)
            res += P[0]

        if P[1] is not None:
            P[1] = bytes_padding(P[1], padding_len)
            res += P[1]
        
        spki['subjectPublicKey'] = BitString(bytes_to_bin(res))

def edit_version(cert, version):
    if version is not None:
        cert['tbsCertificate']['version'] = expr_to_int(version)

    return cert

def edit_serial_number(cert, serial_no):
    if serial_no is not None:
        cert['tbsCertificate']['serialNumber'] = expr_to_int(serial_no)

    return cert

def edit_tbs_signature_algorithm(cert, sig_algo):
    if sig_algo is not None:
        try:
            cert['tbsCertificate']['signature']['algorithm'] = ObjectIdentifier(tuple([expr_to_int(x) for x in sig_algo.split('.')]))
        except Exception as e:
            alert(f"{e}")

    return cert

def edit_validity(cert, start_time, end_time):
    validity = cert['tbsCertificate']['validity']

    if start_time is not None:
        validity[0][0] = UTCTime(start_time)

    if end_time is not None:
        validity[1][0] = UTCTime(end_time)

    return cert

def edit_issuer(cert, types, values):
    issuer = cert['tbsCertificate']['issuer'][0][0]

    if len(types) != len(values):
        if len(types) > len(issuer) or len(values) > len(issuer):
            alert("if the number of specified types/values exceeds the original number, you must provide the corresponding value/type for the extras.")

    if types is not None:
        for i in range(len(types)):
            try:
                issuer[i][0] = ObjectIdentifier(tuple([expr_to_int(x) for x in types[i].split('.')]))
            except Exception as e:
                alert(f"{e}")

    if values is not None:
        for i in range(len(values)):
            issuer[i][1] = UTF8String(values[i])
    
    return cert

def edit_subject(cert, types, values):
    subject = cert['tbsCertificate']['subject'][0][0]

    if (types is not None) and (values is not None):
        if len(types) != len(values):
            if len(types) > len(subject) or len(values) > len(subject):
                alert("if the number of specified types/values exceeds the original number, you must provide the corresponding value/type for the extras.")

    if types is not None:
        for i in range(len(types)):
            try:
                subject[i][0] = ObjectIdentifier(tuple([expr_to_int(x) for x in types[i].split('.')]))
            except Exception as e:
                alert(f"{e}")

    if values is not None:
        for i in range(len(values)):
            subject[i][1] = UTF8String(values[i])

def edit_spki(cert, algo, algo_oid, parameters, pub_key, balanced = False, compressed = False):
    spki = cert['tbsCertificate']['subjectPublicKeyInfo']

    if algo_oid is not None:
        try:
            spki['algorithm']['algorithm'] = ObjectIdentifier(tuple([expr_to_int(x) for x in algo_oid.split('.')]))
        except Exception as e:
            alert(f"{e}")

    if algo == "rsa":
        e, n = pub_key

        set_rsa_public_key(spki, e = e, n = n)

    elif algo == "dsa":
        p, q, g = parameters
        pub = pub_key

        set_dsa_public_key(
                            spki, pub = pub, 
                            p = p, q = q, g = g
        )

    elif algo == "ecdsa":
        curve_name_oid = parameters
        P = pub_key

        set_ecdsa_public_key(
                            spki, curve_name_oid = curve_name_oid, 
                            P_hex = P,
                            compressed = compressed
        )
    
    elif algo == "ecdsa_fp":
        p, a, b, G, order, cofactor, seed = parameters
        P = pub_key

        set_ecdsa_public_key_explicitly(
                                        spki, type = "fp", 
                                        P_hex = P, 
                                        p = p, 
                                        a = a, b = b, 
                                        G_hex = G, 
                                        order = order, 
                                        cofactor = cofactor, seed = seed, 
                                        balanced = balanced, compressed = compressed
        )
    
    elif algo == "ecdsa_f2m_tp":
        m, t, a, b, G, order, cofactor, seed = parameters
        P = pub_key

        set_ecdsa_public_key_explicitly(
                                        spki, type = "f2m_tp", 
                                        P_hex = P, 
                                        degree = m, t3 = t, 
                                        a = a, b = b, 
                                        G_hex = G, 
                                        order = order, 
                                        cofactor = cofactor, seed = seed, 
                                        balanced = balanced, compressed = compressed
        )
    
    elif algo == "ecdsa_f2m_pp":
        m, t3, t2, t1, a, b, G, order, cofactor, seed = parameters
        P = pub_key

        set_ecdsa_public_key_explicitly(
                                        spki, type = "f2m_pp", 
                                        P_hex = P, 
                                        degree = m, t3 = t3, t2 = t2, t1 = t1, 
                                        a = a, b = b, 
                                        G_hex = G, 
                                        order = order, 
                                        cofactor = cofactor, seed = seed, 
                                        balanced = balanced, compressed = compressed
        )

def edit_signature_algorithm(cert, sig_algo):
    if sig_algo is not None:
        try:
            cert['signatureAlgorithm']['algorithm'] = ObjectIdentifier(tuple([expr_to_int(x) for x in sig_algo.split('.')]))
        except Exception as e:
            alert(f"{e}")

    return cert

def edit_signature_value(cert, sig):
    if sig is not None:
        if not is_hex_string(sig):
            alert("the input signature must be a hex string.")

        if len(sig) % 2 == 1:
            sig = '0' + sig

        cert['signature'] = BitString(bytes_to_bin(bytes.fromhex(sig)))

    return cert

def edit_asn1_obj(cert_name, out_path, out_form, idx = None, hex_new_bytes = None, pattern = r'(\d+):d=\d+\s+hl=(\d+)\s+l=\s*(\d+)', valid = True):
    cert_data, pem = read_cert_data(cert_name, ret_pem = True)

    lines = make_lines(cert_name, nl = True, pem = pem)

    if idx is None:
        make_divider("=", 80)
        for i in lines:
            print(i)
        
        make_divider("=", 80)

        prompt("select the line number corresponding to the ASN.1 object you want to modify: ")

        try:
            idx = input("[>] ")
        except KeyboardInterrupt:
            print("")
            sys.exit(1)

        if not idx.isdigit():
            alert("the line number must be an integer.")

        idx = int(idx)

    if idx < 1 or idx > len(lines):
        alert(f"the line number must be an integer between 1 and {len(lines)}.")

    matches = re.findall(pattern, lines[idx - 1])

    if matches:
        start, hl, l = map(int, matches[0])
    else:
        alert("match failed.")
    
    old_bytes = cert_data[start: start + hl + l]

    if hex_new_bytes is None:
        # see https://docs.openssl.org/1.0.2/man3/ASN1_generate_nconf/
        # e.g., UTF8:test    INTEGER:0xFF    FORMAT:HEX, OCTETSTRING:6566    OBJECT:1.2.3.4
        prompt("Please select the method to specify a new ASN.1 object:")
        prompt("1. specify the new ASN.1 object based on a string using `ASN1_generate_nconf(3)` format:")
        prompt("2. specify the new ASN.1 object based on a config file using `ASN1_generate_nconf(3)` format:")
        prompt("3. specify the new DER-encoded ASN.1 object (in hex):")

        try:
            option = input("[>] ")
        except KeyboardInterrupt:
            print("")
            sys.exit(1)

        if option == '1':
            # e.g., UTF8:test    INTEGER:0xFF    FORMAT:HEX, OCTETSTRING:6566    OBJECT:1.2.3.4
            prompt("specify the string corresponding to the new ASN.1 object:")

            try:
                new_asn1_obj_str = input("[>] ")
            except KeyboardInterrupt:
                print("")
                sys.exit(1)

            cmd = "set -e;"
            cmd += f"openssl asn1parse -genstr '{new_asn1_obj_str}' -noout -out /dev/stdout | xxd -p"
            res = run_cmd(cmd)

            hex_new_bytes = res.stdout.strip()
        
        elif option == '2':
            # e.g., 
            # asn1=SEQUENCE:seq_sect
            # 
            # [seq_sect]
            # 
            # field1=BOOL:TRUE
            # field2=EXP:0, UTF8:some random string
            prompt("specify the path of the config file corresponding to the new ASN.1 object:")

            try:
                config_file_name = input("[>] ")
            except KeyboardInterrupt:
                print("")
                sys.exit(1)

            cmd = "set -e;"
            cmd += f"openssl asn1parse -genconf {config_file_name} -noout -out /dev/stdout | xxd -p"
            res = run_cmd(cmd, errors = 'ignore')

            hex_new_bytes = res.stdout.strip()

        elif option == '3':
            prompt("specify the hex string corresponding to the new DER-encoded ASN.1 object:")
            
            try:
                hex_new_bytes = input("[>] ")
            except KeyboardInterrupt:
                print("")
                sys.exit(1)
            
            if not is_hex_string(hex_new_bytes):
                alert("the input must be a hex string.")
        
        else:
            alert("the option must be 1, 2, or 3.")
    
    if len(hex_new_bytes) % 2 == 1:
        hex_new_bytes = '0' + hex_new_bytes

    new_bytes = bytes.fromhex(hex_new_bytes)
    
    new_cert_data = cert_data[:start] + new_bytes + cert_data[start + hl + l:]

    parent_lines = find_parent_lines(lines, lines[idx - 1])[:-1]
    positions = extract_length_field_positions(parent_lines)

    offset = len(new_bytes) - len(old_bytes)
    adjusted_cert_data = adjust_length(new_cert_data, positions, offset)

    write_cert_data(adjusted_cert_data, out_path, pem = (out_form == "pem"))

def export_public_key(cert_path, out_path = None, out_form = "pem"):
    if out_path is None:
        out_path = cert_path

    cert = read_cert(cert_path)
    spki = cert['tbsCertificate']['subjectPublicKeyInfo']
    
    der = encoder.encode(spki)

    filename = change_suffix(cert_path)

    if out_form == "pem":
        pem = der_to_pem("-----BEGIN PUBLIC KEY-----\n", "-----END PUBLIC KEY-----\n", der)
        open(filename, "w").write(pem)

    else:
        open(filename, "wb").write(der)
    
    prompt(f"public key export successfully, named [{filename}].")
