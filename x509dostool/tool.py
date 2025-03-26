#!/usr/bin/env python3

import os
import argparse
import pkg_resources

from .func.generate import *
from .func.edit import *
from .func.detect import *

from .misc.misc import *

globals().update(load_config(pkg_resources.resource_filename('x509dostool', 'config.json')))

def main():
    if BANNER_FLAG == True:
        print(BANNER)
    
    TMP_DIR = DEFAULT_TMP_DIR
    if TMP_DIR_RANDOM_FLAG:
        TMP_DIR += os.urandom(5).hex() + '/'

    parser = argparse.ArgumentParser(description = "Test Tool (v1.0.1)", usage = argparse.SUPPRESS)
    subparser = parser.add_subparsers(dest = 'command', required = True)

    # main
    generate = subparser.add_parser('generate', help = "rapid generation of crafted certificates")
    edit = subparser.add_parser('edit', help = "customized edit of certificates")
    detect = subparser.add_parser('detect', help = "detection of implementations in libraries")

    generate_out_group = generate.add_argument_group(title = "output settings")
    generate_out_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_NAME})', metavar = "", required = False, default = DEFAULT_CERT_NAME)
    generate_out_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {pem, der}, default = pem', metavar = "", required = False, default = "pem")

    # 
    generate_subparser = generate.add_subparsers(dest = 'generate_command')

    # ================================ BEGIN test0 ================================
    generate_test0 = generate_subparser.add_parser("test0", help = "a normal certificate")
    
    generate_test0.add_argument('-algo', type = str, help = 'specify the public key algorithm: {rsa, dsa, ecdsa} (default = ecdsa)', choices = ['rsa', 'dsa', 'ecdsa'], metavar = "", required = False, default = 'ecdsa')

    generate_test0_add_group = generate_test0.add_argument_group(title = "additional features (only worked for `-algo ecdsa`)")
    generate_test0_add_group.add_argument('-name', type = str, help = 'specify the curve name (default = prime256v1)', choices = list(CURVE_NAME_DIC.keys()), metavar = "", required = False, default = "prime256v1")
    generate_test0_add_group.add_argument("--explicit", action='store_true', help = "enable explicit inclusion of curve parameters", required = False)
    generate_test0_add_group.add_argument('--compressed', action = 'store_true', help = 'enable point compression', required = False)

    #generate_test0_output_group = generate_test0.add_argument_group(title = "output settings")
    #generate_test0_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_NAME})', metavar = "", required = False, default = DEFAULT_CERT_NAME)
    #generate_test0_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = der)', metavar = "", required = False, default = "der")    
    # ================================= END test0 ================================


    # ================================ BEGIN test1 ================================
    generate_test1 = generate_subparser.add_parser("test1", help = "a cert explicitly containing a reduction polynomial of degree m, where m is very large")
    generate_test1.add_argument('-m', type = str, help = 'specify the degree m (default = randint(0x7FFFFF, 0x7FFFFFFF))', metavar = "", required = False)

    generate_test1_add_group = generate_test1.add_argument_group(title = "additional features")
    generate_test1_add_group.add_argument('--balanced', action = 'store_true', help = 'add leading zero bytes', required = False)
    generate_test1_add_group.add_argument('--compressed', action = 'store_true', help = 'enable point compression', required = False)

    #generate_test1_output_group = generate_test1.add_argument_group(title = "output settings")
    #generate_test1_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_NAME})', metavar = "", required = False, default = DEFAULT_CERT_NAME)
    #generate_test1_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = der)', metavar = "", required = False, default = "der")    
    # ================================= END test1 ================================


    # ================================ BEGIN test2 ================================
    generate_test2 = generate_subparser.add_parser("test2", help = "a cert explicitly containing a reduction polynomial f(x) = x^m + x^t + 1, with m < t")
    generate_test2.add_argument('-m', type = str, help = 'specify the degree m (default = randint(112, 384))', metavar = "", required = False)
    generate_test2.add_argument('-t', type = str, help = 'specify the exponent t (default = randint(385, 571))', metavar = "", required = False)

    generate_test2_add_group = generate_test2.add_argument_group(title = "additional features")
    generate_test2_add_group.add_argument('--balanced', action = 'store_true', help = 'add leading zero bytes', required = False)
    generate_test2_add_group.add_argument('--compressed', action = 'store_true', help = 'enable point compression', required = False)

    #generate_test2_output_group = generate_test2.add_argument_group(title = "output settings")
    #generate_test2_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_NAME})', metavar = "", required = False, default = DEFAULT_CERT_NAME)
    #generate_test2_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = der)', metavar = "", required = False, default = "der")    
    # ================================= END test2 ================================


    # ================================ BEGIN test3 ================================
    generate_test3 = generate_subparser.add_parser("test3", help = "a cert explicitly containing a crafted curve E_p(a, b), where p is a non-prime")
    generate_test3.add_argument('-p', type = str, help = 'specify the prime p', metavar = "", required = False)

    generate_test3_add_group = generate_test3.add_argument_group(title = "additional features")
    generate_test3_add_group.add_argument('--balanced', action = 'store_true', help = 'add leading zero bytes', required = False)
    # generate_test3_add_group.add_argument('--compressed', action = 'store_true', help = 'enable point compression', required = False)

    #generate_test3_output_group = generate_test3.add_argument_group(title = "output settings")
    #generate_test3_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_NAME})', metavar = "", required = False, default = DEFAULT_CERT_NAME)
    #generate_test3_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = der)', metavar = "", required = False, default = "der")    
    #generate_test3_add_group.add_argument('--compressed', action = 'store_true', help = 'enable point compression', required = False)
    # ================================= END test3 ================================


    # ================================ BEGIN test4 ================================
    generate_test4 = generate_subparser.add_parser("test4", help = "a cert explicitly containing a curve over F_p, where p is very large")
    generate_test4.add_argument('-p', type = str, help = 'specify the prime p (default = choice(the 25th to 35th Mersenne primes))', metavar = "", required = False)
    
    generate_test4_add_group = generate_test4.add_argument_group(title = "additional features")
    generate_test4_add_group.add_argument('--balanced', action = 'store_true', help = 'add leading zero bytes', required = False)
    generate_test4_add_group.add_argument('--compressed', action = 'store_true', help = 'enable point compression', required = False)

    #generate_test4_output_group = generate_test4.add_argument_group(title = "output settings")
    #generate_test4_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_NAME})', metavar = "", required = False, default = DEFAULT_CERT_NAME)
    #generate_test4_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = der)', metavar = "", required = False, default = "der")    
    # ================================= END test4 ================================


    # ================================ BEGIN test5 ================================
    generate_test5 = generate_subparser.add_parser("test5", help = "a cert containing a large number of names/name constraints/policies")
    generate_test5.add_argument('-emails', type = str, help = "specify the number of the subject's email addresses (default = 0)", metavar = "", required = False)
    generate_test5.add_argument('-sans', type = str, help = 'specify the number of subject alternative names (default = 30000)', metavar = "", required = False)
    generate_test5.add_argument('-ncs', type = str, help = 'specify the number of name constraints (default = 0)', metavar = "", required = False)
    generate_test5.add_argument('-policies', type = str, help = 'specify the number of policies (default = 0)', metavar = "", required = False)
    
    #generate_test5_output_group = generate_test5.add_argument_group(title = "output settings")
    #generate_test5_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_NAME})', metavar = "", required = False, default = DEFAULT_CERT_NAME)
    #generate_test5_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = der)', metavar = "", required = False, default = "der")    
    # ================================= END test5 ================================


    # ================================ BEGIN test6 ================================
    generate_test6 = generate_subparser.add_parser("test6", help = "a cert containing a UTF8String with a very large length field")
    generate_test6.add_argument("-length", type = str, help = "specify the content length claimed in the length field (default = 0x0500000000 bytes)", metavar = "", required = False)

    #generate_test6_output_group = generate_test6.add_argument_group(title = "output settings")
    #generate_test6_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_NAME})', metavar = "", required = False, default = DEFAULT_CERT_NAME)
    #generate_test6_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = der)', metavar = "", required = False, default = "der")    
    # ================================= END test6 ================================


    # ================================ BEGIN test7 ================================
    generate_test7 = generate_subparser.add_parser("test7", help = "a cert containing an OID with a very large sub-identifier")
    #generate_test7.add_argument("-sub_id", type = str, help = "specify the sub-identifier (default = 2^randint(10000, 1000000) - 1)", metavar = "", required = False)
    generate_test7.add_argument("-length", type = str, help = "specify the length of the DER-encoded sub-identifier (default = 1000000 bytes)", metavar = "", required = False)
    
    #generate_test7_output_group = generate_test7.add_argument_group(title = "output settings")
    #generate_test7_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_NAME})', metavar = "", required = False, default = DEFAULT_CERT_NAME)
    #generate_test7_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = der)', metavar = "", required = False, default = "der")    
    # ================================= END test7 ================================


    # ================================ BEGIN test8 ================================
    generate_test8 = generate_subparser.add_parser("test8", help = "a cert chain where each cert contains a large number of names/name constraints.")
    generate_test8.add_argument('-num', type = str, help = 'specify the number of certs (default = 3)', metavar = "", required = False)    
    generate_test8.add_argument('-sans', type = str, help = 'specify the number of subject alternative names in each cert (default = 30000)', metavar = "", required = False)
    generate_test8.add_argument('-ncs', type = str, help = 'specify the number of name constraints in each cert (default = 30000)', metavar = "", required = False)
    
    #generate_test8_output_group = generate_test8.add_argument_group(title = "output settings")
    #generate_test8_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_CHAIN_NAME})', metavar = "", required = False, default = DEFAULT_CERT_CHAIN_NAME)
    #generate_test8_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = pem)', metavar = "", required = False, default = "pem")    
    # ================================= END test8 ================================


    # ================================ BEGIN test9 ================================
    generate_test9 = generate_subparser.add_parser("test9", help = "a cert chain where each cert contains a large number of policies and a full Cartesian product of mappings")
    generate_test9.add_argument('-num', type = str, help = 'specify the number of certs (default = 30)', metavar = "", required = False)    
    generate_test9.add_argument('-policies', type = str, help = 'specify the number of policies in each cert (default = 2)', metavar = "", required = False)

    generate_test9_add_group = generate_test9.add_argument_group(title = "additional features")
    generate_test9_add_group.add_argument('--mapping', action = 'store_true', help = "enable policy mappings", required = False)

    #generate_test9_output_group = generate_test9.add_argument_group(title = "output settings")
    #generate_test9_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_CHAIN_NAME})', metavar = "", required = False, default = DEFAULT_CERT_CHAIN_NAME)
    #generate_test9_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = pem)', metavar = "", required = False, default = "pem")    
    # ================================= END test9 ================================


    # ================================ BEGIN test10 ================================
    generate_test10 = generate_subparser.add_parser("test10", help = "a cert chain forming a cycle")
    generate_test10.add_argument('-num', type = str, help = 'specify the number of certs (default = 3)', metavar = "", required = False)
    generate_test10.add_argument('-repeat', type = str, help = 'specify the number of times the loop should repeat, repeat = 0 means original (only worked for `-outform pem`, default = 1)', metavar = "", required = False)
    
    #generate_test10_output_group = generate_test10.add_argument_group(title = "output settings")
    #generate_test10_output_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_CERT_CHAIN_NAME})', metavar = "", required = False, default = DEFAULT_CERT_CHAIN_NAME)
    #generate_test10_output_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {der, pem} (default = pem)', metavar = "", required = False, default = "pem")    
    # ================================= END test10 ================================



    # edit
    edit_in_group = edit.add_argument_group(title = "input settings")
    edit_in_group.add_argument('-in', dest = "input", type = str, help = f'specify an input path', metavar = "", required = True)

    edit_out_group = edit.add_argument_group(title = "output settings")
    edit_out_group.add_argument('-out', type = str, help = f'specify an output path (default = {DEFAULT_EDITED_CERT_NAME})', metavar = "", required = False, default = DEFAULT_EDITED_CERT_NAME)
    edit_out_group.add_argument('-outform', type = str, choices = ['der', 'pem'], help = 'specify a encoding format: {pem, der}, default = pem', metavar = "", required = False, default = "pem")
    edit_out_group.add_argument('--pubout', action = 'store_true', help = 'export the public key synchronously', required = False)

    #
    edit_subparser = edit.add_subparsers(dest = 'edit_command')
    
    # tbsCertificate
    edit_tbs = edit_subparser.add_parser("tbs", help = "edit the tbsCertificate field")

    # signatureAlgorithm
    edit_sig_algo = edit_subparser.add_parser("sig_algo", help = "edit the signatureAlgorithm field")
    edit_sig_algo.add_argument('-algo', dest = "sig_algo_oid", type = str, help = 'specify the signature algorithm (in dot-decimal notation)', metavar = "", required = True)

    # signatureValue
    edit_sig = edit_subparser.add_parser("sig", help = "edit the signatureValue field")
    edit_sig.add_argument('-sig', type = str, help = 'specify the signature (in hex)', metavar = "", required = True)

    # asn.1 objects
    edit_asn1 = edit_subparser.add_parser("asn1", help = "edit a specific ASN.1 object directly")

    # 
    edit_sub_subparser = edit_tbs.add_subparsers(dest = 'edit_sub_command')
    
    # ================================ BEGIN version ================================
    edit_tbs_ver = edit_sub_subparser.add_parser("ver", help = "edit the version field")
    edit_tbs_ver.add_argument('-ver', type = str, help = 'specify the version', metavar = "", required = True)    
    # ================================= END version ================================


    # ================================ BEGIN serialNumber ================================
    edit_tbs_sn = edit_sub_subparser.add_parser("sn", help = "edit the serialNumber field")
    edit_tbs_sn.add_argument('-sn', type = str, help = 'specify the serial number', metavar = "", required = True)
    # ================================= END serialNumber ================================
    

    # ================================ BEGIN signature ================================
    edit_tbs_sig = edit_sub_subparser.add_parser("sig", help = "edit the signature field")
    edit_tbs_sig.add_argument('-algo', dest = "tbs_sig_algo_oid", type = str, help = 'specify the signature algorithm (in dot-decimal notation)', metavar = "", required = True)
    # ================================= END signature ================================


    # ================================ BEGIN issuer ================================
    edit_tbs_issuer = edit_sub_subparser.add_parser("issuer", help = "edit the issuer field")
    edit_tbs_issuer.add_argument('-types', nargs = '+', dest = "issuer_types", type = str, help = 'specify the list of name types (in dot-decimal notation)', metavar = "", required = False, default = [])
    edit_tbs_issuer.add_argument('-values', nargs = '+', dest = "issuer_values", type = str, help = 'specify the list of name values', metavar = "", required = False, default = [])
    # ================================= END issuer ================================


    # ================================ BEGIN validity ================================
    edit_tbs_validity = edit_sub_subparser.add_parser("validity", help = "edit the validity field")
    edit_tbs_validity.add_argument('-start', type = str, help = 'specify the start time', metavar = "", required = False)
    edit_tbs_validity.add_argument('-end', type = str, help = 'specify the end time', metavar = "", required = False)
    # ================================= END validity ================================


    # ================================ BEGIN subject ================================
    edit_tbs_subject = edit_sub_subparser.add_parser("subject", help = "edit the subject field")
    edit_tbs_subject.add_argument('-types', nargs = '+', dest = "subject_types", type = str, help = 'specify the list of name types (in dot-decimal notation)', metavar = "", required = False, default = [])
    edit_tbs_subject.add_argument('-values', nargs = '+', dest = "subject_values", type = str, help = 'specify the list of name values', metavar = "", required = False, default = [])
    # ================================= END subject ================================


    # ================================ BEGIN subjectPublicKeyInfo ================================
    edit_tbs_spki = edit_sub_subparser.add_parser("spki", help = "edit the subjectPublicKeyInfo field")

    #
    edit_sub_sub_subparser = edit_tbs_spki.add_subparsers(dest = 'edit_sub_sub_command')

    # rsa
    edit_tbs_spki_rsa = edit_sub_sub_subparser.add_parser("rsa", help = "edit the rsa public key")
    edit_tbs_spki_rsa.add_argument('-algo', dest = "pub_algo_oid", type = str, help = 'specify the public key algorithm (in dot-decimal notation)', metavar = "", required = False)

    edit_tbs_spki_rsa.add_argument('-e', type = str, help = 'specify the exponent e', metavar = "", required = False)
    edit_tbs_spki_rsa.add_argument('-n', type = str, help = 'specify the modulus n', metavar = "", required = False)

    # dsa
    edit_tbs_spki_dsa = edit_sub_sub_subparser.add_parser("dsa", help = "edit the dsa public key")
    edit_tbs_spki_dsa.add_argument('-algo', dest = "pub_algo_oid", type = str, help = 'specify the public key algorithm (in dot-decimal notation)', metavar = "", required = False)

    edit_tbs_spki_dsa.add_argument('-p', type = str, help = 'specify the parameter p', metavar = "", required = False)
    edit_tbs_spki_dsa.add_argument('-q', type = str, help = 'specify the parameter q', metavar = "", required = False)
    edit_tbs_spki_dsa.add_argument('-g', type = str, help = 'specify the parameter g', metavar = "", required = False)
    edit_tbs_spki_dsa.add_argument('-pub', type = str, help = 'specify the public key', metavar = "", required = False)

    # ecdsa
    edit_tbs_spki_ecdsa = edit_sub_sub_subparser.add_parser("ecdsa", help = "edit the ecdsa public key")
    edit_tbs_spki_ecdsa.add_argument('-algo', dest = "pub_algo_oid", type = str, help = 'specify the public key algorithm (in dot-decimal notation)', metavar = "", required = False)

    edit_tbs_spki_ecdsa.add_argument("-name", type = str, choices = list(CURVE_NAME_DIC.keys()), help = 'specify the curve name', metavar = "", required = False)
    edit_tbs_spki_ecdsa.add_argument("-P", dest = "P", type = str, help = 'specify the public key point (in hex) (the first byte should be 02/03/04)', metavar = "", required = False)

    edit_tbs_spki_ecdsa_group = edit_tbs_spki_ecdsa.add_argument_group(title = "additional features")
    edit_tbs_spki_ecdsa_group.add_argument('--compressed', action = 'store_true', help = 'enable point compression', required = False)

    # ecdsa E_(F_p) (explicit)
    edit_tbs_spki_ecdsa_fp = edit_sub_sub_subparser.add_parser("ecdsa_fp", help = "edit the ecdsa public key (explicit: E_(F_p))")
    edit_tbs_spki_ecdsa_fp.add_argument('-algo', dest = "pub_algo_oid", type = str, help = 'specify the public key algorithm (in dot-decimal notation)', metavar = "", required = False)

    edit_tbs_spki_ecdsa_fp.add_argument('-p', type = str, help = 'specify the prime p', metavar = "", required = False)
    edit_tbs_spki_ecdsa_fp.add_argument('-a', type = str, help = 'specify the parameter a of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_fp.add_argument('-b', type = str, help = 'specify the parameter b of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_fp.add_argument("-G", type = str, help = 'specify the base point (in hex) (the first byte should be 02/03/04)', metavar = "", required = False)
    edit_tbs_spki_ecdsa_fp.add_argument("-order", type = str, help = 'specify the order of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_fp.add_argument("-cofactor", type = str, help = 'specify the cofactor of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_fp.add_argument("-seed", type = str, help = 'specify the seed of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_fp.add_argument("-P", type = str, help = 'specify the public key point (in hex) (the first byte should be 02/03/04)', metavar = "", required = False)

    edit_tbs_spki_ecdsa_fp_group = edit_tbs_spki_ecdsa_fp.add_argument_group(title = "additional features")
    edit_tbs_spki_ecdsa_fp_group.add_argument('--balanced', action = 'store_true', help = 'add leading zero bytes', required = False)
    edit_tbs_spki_ecdsa_fp_group.add_argument('--compressed', action = 'store_true', help = 'enable point compression', required = False)

    # ecdsa E_(F_(2^m)), trinomial (explicit)
    edit_tbs_spki_ecdsa_f2m_tp = edit_sub_sub_subparser.add_parser("ecdsa_f2m_tp", help = "edit the ecdsa public key (explicit: E_(F_(2^m)), f(x) = x^m + x^t + 1)")
    edit_tbs_spki_ecdsa_f2m_tp.add_argument('-algo', dest = "pub_algo_oid", type = str, help = 'specify the public key algorithm (in dot-decimal notation)', metavar = "", required = False)

    edit_tbs_spki_ecdsa_f2m_tp.add_argument('-m', type = str, help = 'specify the degree m', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_tp.add_argument('-t', type = str, help = 'specify the exponent t', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_tp.add_argument('-a', type = str, help = 'specify the parameter a of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_tp.add_argument('-b', type = str, help = 'specify the parameter b of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_tp.add_argument("-G", type = str, help = 'specify the base point (in hex) (the first byte should be 02/03/04)', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_tp.add_argument("-order", type = str, help = 'specify the order of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_tp.add_argument("-cofactor", type = str, help = 'specify the cofactor of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_tp.add_argument("-seed", type = str, help = 'specify the seed of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_tp.add_argument("-P", type = str, help = 'specify the public key point (in hex) (the first byte should be 02/03/04)', metavar = "", required = False)

    edit_tbs_spki_ecdsa_f2m_tp_group = edit_tbs_spki_ecdsa_f2m_tp.add_argument_group(title = "additional features")
    edit_tbs_spki_ecdsa_f2m_tp_group.add_argument('--balanced', action = 'store_true', help = 'add leading zero bytes', required = False)
    edit_tbs_spki_ecdsa_f2m_tp_group.add_argument('--compressed', action = 'store_true', help = 'enable point compression', required = False)

    # ecdsa E_(F_(2^m)), pentanomial (explicit)
    edit_tbs_spki_ecdsa_f2m_pp = edit_sub_sub_subparser.add_parser("ecdsa_f2m_pp", help = "edit the ecdsa public key (explicit: E_(F_(2^m)), f(x) = x^m + x^t3 + x^t2 + x^t1 + 1)")
    edit_tbs_spki_ecdsa_f2m_pp.add_argument('-algo', dest = "pub_algo_oid", type = str, help = 'specify the public key algorithm (in dot-decimal notation)', metavar = "", required = False)

    edit_tbs_spki_ecdsa_f2m_pp.add_argument('-m', type = str, help = 'specify the degree m', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_pp.add_argument('-t3', type = str, help = 'specify the exponent t3', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_pp.add_argument('-t2', type = str, help = 'specify the exponent t3', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_pp.add_argument('-t1', type = str, help = 'specify the exponent t3', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_pp.add_argument('-a', type = str, help = 'specify the parameter a of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_pp.add_argument('-b', type = str, help = 'specify the parameter b of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_pp.add_argument("-G", type = str, help = 'specify the base point (in hex) (the first byte should be 02/03/04)', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_pp.add_argument("-order", type = str, help = 'specify the order of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_pp.add_argument("-cofactor", type = str, help = 'specify the cofactor of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_pp.add_argument("-seed", type = str, help = 'specify the seed of the curve', metavar = "", required = False)
    edit_tbs_spki_ecdsa_f2m_pp.add_argument("-P", dest = "P", type = str, help = 'specify the public key point (in hex) (the first byte should be 02/03/04)', metavar = "", required = False)

    edit_tbs_spki_ecdsa_f2m_pp_group = edit_tbs_spki_ecdsa_f2m_pp.add_argument_group(title = "additional features")
    edit_tbs_spki_ecdsa_f2m_pp_group.add_argument('--balanced', action = 'store_true', help = 'add leading zero bytes', required = False)
    edit_tbs_spki_ecdsa_f2m_pp_group.add_argument('--compressed', action = 'store_true', help = 'enable point compression', required = False)
    # ================================= END subjectPublicKeyInfo ================================


    # detect
    detect_in_group = detect.add_argument_group(title = "input settings")

    detect_in_group.add_argument('-libs', type = str, help = "specify the path of the script file(s) for the libraries to be detected", metavar = "", required = True)
    detect_in_group.add_argument('-certs', type = str, help = "specify the path of the certificate(s)", metavar = "", required = True)

    # 
    if len(sys.argv) == 1:
        sys.argv.append('-h')
    
    if len(sys.argv) == 2:
        if sys.argv[1] == "generate":
            generate.print_help()
            sys.exit(1)

        if sys.argv[1] == "edit":
            edit.print_help()
            sys.exit(1)
        
        if sys.argv[1] == "detect":
            detect.print_help()
            sys.exit(1)

    # 
    args = parser.parse_args()

    # debug mode
    if DEBUG_FLAG:
        print(args)

    if args.command == "generate":

        os.makedirs(TMP_DIR, exist_ok = True)

        # create folder
        if args.out is not None:
            dirs = os.path.dirname(args.out)
    
            if dirs != '':
                os.makedirs(dirs, exist_ok = True)

        if args.generate_command is None:
            generate.print_help()
            sys.exit(1)

        else:
            prompt("generating...")
            
            if args.generate_command == 'test0':
                gen_test0(
                            type = args.algo, 
                            curve_name = args.name, 
                            explicit = args.explicit, 
                            compressed = args.compressed, 
                            out_path = args.out, out_form = args.outform,
                            tmp_dir = TMP_DIR
                )

            elif args.generate_command == 'test1':
                gen_test1(
                        m = args.m, 
                        balanced = args.balanced, compressed = args.compressed, 
                        out_path = args.out, out_form = args.outform,
                        tmp_dir = TMP_DIR
                )

            elif args.generate_command == 'test2':
                gen_test2(
                        m = args.m, t = args.t, 
                        balanced = args.balanced, compressed = args.compressed, 
                        out_path = args.out, out_form = args.outform,
                        tmp_dir = TMP_DIR
                )

            elif args.generate_command == 'test3':
                gen_test3(
                        p = args.p, 
                        balanced = args.balanced, 
                        out_path = args.out, out_form = args.outform,
                        tmp_dir = TMP_DIR
                )

            elif args.generate_command == 'test4':
                gen_test4(
                        p = args.p, 
                        balanced = args.balanced, compressed = args.compressed, 
                        out_path = args.out, out_form = args.outform,
                        tmp_dir = TMP_DIR
                )
        
            elif args.generate_command == 'test5':
                gen_test5(
                        num_emails = args.emails,
                        num_alt_names = args.sans, 
                        num_name_constraints = args.ncs, 
                        num_policies = args.policies, 
                        out_path = args.out, out_form = args.outform,
                        tmp_dir = TMP_DIR
                )
        
            elif args.generate_command == 'test6':
                gen_test6(
                        length = args.length, 
                        out_path = args.out, out_form = args.outform,
                        tmp_dir = TMP_DIR
                )
        
            elif args.generate_command == 'test7':
                gen_test7(
                        sub_id_encoded_length = args.length, 
                        out_path = args.out, out_form = args.outform,
                        tmp_dir = TMP_DIR
                )
        
            elif args.generate_command == 'test8':
                gen_test8(
                        num_certs = args.num, 
                        num_alt_names = args.sans, num_name_constraints = args.ncs, 
                        out_path = args.out, out_form = args.outform,
                        tmp_dir = TMP_DIR
                )
        
            elif args.generate_command == 'test9':
                gen_test9(
                        num_certs = args.num, 
                        num_policies = args.policies, 
                        mapping = args.mapping, 
                        out_path = args.out, out_form = args.outform,
                        tmp_dir = TMP_DIR
                )
        
            elif args.generate_command == 'test10':
                gen_test10(
                        num_certs = args.num, repeat = args.repeat,
                        out_path = args.out, out_form = args.outform,
                        tmp_dir = TMP_DIR
                )

            if args.generate_command in ['test8', 'test9', 'test10']:
                if args.outform == "pem":
                    prompt(f"certificate chain generated successfully, named [{args.out}].")

                else:
                    prompt("certificates in DER format are not supported for merging into a single certificate chain file, so we did not merge them.")
                    prompt(f"these certificates can be found in folder [{os.path.abspath(TMP_DIR)}].")

            else:
                prompt(f"certificate generated successfully, named [{args.out}].")

            prompt(f"other relevant files generated during this process can be found in folder [{os.path.abspath(TMP_DIR)}].")


    elif args.command == "edit":
        
        # create folder
        if args.out is not None:
            dirs = os.path.dirname(args.out)
    
            if dirs != '':
                os.makedirs(dirs, exist_ok = True)

        if args.edit_command is None:
            cert = read_cert(args.input)

            write_cert(cert, args.out, pem = (args.outform == 'pem'))

        elif args.edit_command == 'asn1':
            edit_asn1_obj(args.input, args.out, args.outform)
        
        else:
            cert = read_cert(args.input)

            if args.edit_command == 'tbs':
                if args.edit_sub_command is None:
                    edit_tbs.print_help()
                    sys.exit(1)

                elif args.edit_sub_command == 'ver':
                    edit_version(cert, args.ver)

                elif args.edit_sub_command == 'sn':
                    edit_serial_number(cert, args.sn)

                elif args.edit_sub_command == 'sig':
                    edit_tbs_signature_algorithm(cert, args.tbs_sig_algo_oid)

                elif args.edit_sub_command == 'issuer':

                    if all(arg == [] for arg in [args.issuer_types, args.issuer_values]):
                        print("usage: edit tbs issuer [-h] [-types  [...]] [-values  [...]]")
                        print("edit tbs issuer: error: one of the following arguments are required: -types, -values")
                        sys.exit(1)

                    edit_issuer(cert, args.issuer_types, args.issuer_values)

                elif args.edit_sub_command == 'validity':

                    if all(arg is None for arg in [args.start, args.end]):
                        print("usage: edit tbs validity [-h] [-start] [-end]")
                        print("edit tbs validity: error: one of the following arguments are required: -start, -end")
                        sys.exit(1)

                    edit_validity(cert, args.start, args.end)

                elif args.edit_sub_command == 'subject':

                    if all(arg == [] for arg in [args.subject_types, args.subject_values]):
                        print("usage: edit tbs subject [-h] [-types  [...]] [-values  [...]]")
                        print("edit tbs subject: error: one of the following arguments are required: -types, -values")
                        sys.exit(1)

                    edit_subject(cert, args.subject_types, args.subject_values)

                elif args.edit_sub_command == 'spki':

                    if args.edit_sub_sub_command is None:
                        edit_tbs_spki.print_help()
                        sys.exit(1)
                    
                    if args.edit_sub_sub_command == "rsa":
                        parameters = None
                        pub_key = [args.e, args.n]

                        if all(arg is None for arg in [args.pub_algo_oid] + [parameters] + pub_key):
                            print("usage: edit tbs spki rsa [-h] [-algo] [-e] [-n]")
                            print("edit tbs spki rsa: error: one of the following arguments are required: -algo, -e, -n")
                            sys.exit(1)

                        edit_spki(
                                    cert, "rsa", args.pub_algo_oid, 
                                    parameters, pub_key
                        )

                    elif args.edit_sub_sub_command == "dsa":
                        parameters = [args.p, args.q, args.g]
                        pub_key = args.pub

                        if all(arg is None for arg in [args.pub_algo_oid] + parameters + [pub_key]): 
                            print("usage: edit tbs spki dsa [-h] [-algo] [-p] [-q] [-g] [-pub]")
                            print("edit tbs spki dsa: error: one of the following arguments are required: -algo, -p, -q, -g, -pub")
                            sys.exit(1)

                        edit_spki(
                                    cert, "dsa", args.pub_algo_oid, 
                                    parameters, pub_key
                        )

                    elif args.edit_sub_sub_command == "ecdsa":
                        if args.name is None:
                            parameters = None
                        else:
                            parameters = CURVE_NAME_DIC[args.name]

                        pub_key = args.P

                        if all(arg is None for arg in [args.pub_algo_oid] + [parameters] + [pub_key]):

                            if not any([args.compressed]):
                                print("usage: edit tbs spki ecdsa [-h] [-algo] [-name] [-P] [--compressed]")
                                print("edit tbs spki ecdsa: error: one of the following arguments are required: -algo, -name, -P, --compressed")
                                sys.exit(1)

                        edit_spki(
                                    cert, "ecdsa", args.pub_algo_oid, 
                                    parameters, pub_key, 
                                    compressed = args.compressed
                        )

                    elif args.edit_sub_sub_command == "ecdsa_fp":
                        parameters = [
                                        args.p, 
                                        args.a, args.b, args.G,  
                                        args.order, args.cofactor, args.seed
                        ]
                        pub_key = args.P

                        if all(arg is None for arg in [args.pub_algo_oid] + parameters + [pub_key]):
                            if not any([args.balanced, args.compressed]):
                                print("usage: edit tbs spki ecdsa_fp [-h] [-algo] [-p] [-a] [-b] [-G] [-order] [-cofactor] [-seed] [-P] [--balanced] [--compressed]")
                                print("edit tbs spki ecdsa_fp: error: one of the following arguments are required: -algo, -p, -a, -b, -G, -order, -cofactor, -seed, -P, --balanced, --compressed")
                                sys.exit(1)                        

                        edit_spki(
                                    cert, "ecdsa_fp", args.pub_algo_oid, 
                                    parameters, pub_key, 
                                    balanced = args.balanced, compressed = args.compressed
                        )

                    elif args.edit_sub_sub_command == "ecdsa_f2m_tp":
                        parameters = [
                                        args.m, args.t,
                                        args.a, args.b, args.G, 
                                        args.order, args.cofactor, args.seed
                        ]
                        pub_key = args.P

                        if all(arg is None for arg in [args.pub_algo_oid] + parameters + [pub_key]):

                            if not any([args.balanced, args.compressed]):
                                print("usage: edit tbs spki ecdsa_f2m_tp [-h] [-algo] [-m] [-t] [-a] [-b] [-G] [-order] [-cofactor] [-seed] [-P] [--balanced] [--compressed]")
                                print("edit tbs spki ecdsa_f2m_tp: error: one of the following arguments are required: -algo, -m, -t, -a, -b, -G, -order, -cofactor, -seed, -P, --balanced, --compressed")
                                sys.exit(1)  

                        edit_spki(
                                    cert, "ecdsa_f2m_tp", args.pub_algo_oid, 
                                    parameters, pub_key, 
                                    balanced = args.balanced, compressed = args.compressed
                        )

                    elif args.edit_sub_sub_command == "ecdsa_f2m_pp":
                        parameters = [
                                        args.m, args.t3, args.t2, args.t1,
                                        args.a, args.b, args.G, 
                                        args.order, args.cofactor, args.seed
                        ]
                        pub_key = args.P

                        if all(arg is None for arg in [args.pub_algo_oid] + parameters + [pub_key]):

                            if not any([args.balanced, args.compressed]):
                                print("usage: edit tbs spki ecdsa_f2m_pp [-h] [-algo] [-m] [-t3] [-t2] [-t1] [-a] [-b] [-G] [-order] [-cofactor] [-seed] [-P] [--balanced] [--compressed]")
                                print("edit tbs spki ecdsa_f2m_pp: error: one of the following arguments are required: -algo, -m, -t3, -t2, -t1, -a, -b, -G, -order, -cofactor, -seed, -P, --balanced, --compressed")
                                sys.exit(1) 

                        edit_spki(
                                    cert, "ecdsa_f2m_pp", args.pub_algo_oid, 
                                    parameters, pub_key, 
                                    balanced = args.balanced, compressed = args.compressed
                        )

            elif args.edit_command == 'sig_algo':
                if args.sig_algo_oid is not None:
                    edit_signature_algorithm(cert, args.sig_algo_oid)

            elif args.edit_command == 'sig':
                if args.sig is not None:
                    edit_signature_value(cert, args.sig)

            write_cert(cert, args.out, pem = (args.outform == 'pem'))
        
        prompt(f"certificate edited successfully, named [{args.out}].")

        if args.pubout:
            export_public_key(args.out, None, args.outform)

    elif args.command == "detect":
        lib_path = args.libs
        cert_path = args.certs

        handle_detects(lib_path, cert_path, CPU_ROUNDS, MEM_ROUNDS, CPU_USAGE_AVG_THRESHOLD, MEM_USAGE_AVG_THRESHOLD)

    prompt("finished")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")
        sys.exit(1)
    except Exception as e:
        alert(f"{e}")