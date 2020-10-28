import csv
import sys
import ssl
import time
import socket
import log
import requests
import threading
import itertools
import concurrent
import datetime
import random
import os
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.x509 import load_pem_x509_certificate, ocsp

from concurrent.futures import ThreadPoolExecutor
threadLock = threading.Lock()

# Importing color module
from colorama import Fore, init, Style
init()

LOGGER = log.setup_logger("cert_check", con_level=0)
__author__ = "Febin Jose"
__version__ = "2.0"

THREADS = 50
CSV_FILE = "output.csv"
COMPLETE = 0

Certificate_Dict = {'Hostname': "", "Status": "", "PTR/A Record": "", "OCSP": "", "Issued To": "", "Issuer": "",
                    "Subject": "", "Subject Alternative Names": "", "Valid From": "", "Valid To":"", "Expired": "",
                    "Expire Soon": "", "Revocation Status": "", "Self Signed": "", "Serial Num": "", "Version": "",
                    "Comments": ""}


def welcome():
    welcome_text = """
        ░▒█▀▀▄░█▀▀░█▀▀▄░▀█▀░░░▒█▀▀▄░█░░░░█▀▀░█▀▄░█░▄░█▀▀░█▀▀▄
        ░▒█░░░░█▀▀░█▄▄▀░░█░░░░▒█░░░░█▀▀█░█▀▀░█░░░█▀▄░█▀▀░█▄▄▀
        ░▒█▄▄▀░▀▀▀░▀░▀▀░░▀░░░░▒█▄▄▀░▀░░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░▀▀   """
    print(f"{Fore.LIGHTBLUE_EX}{welcome_text}", end="")
    print(f"{Fore.LIGHTGREEN_EX}  █{Fore.LIGHTRED_EX} version {__version__}{Fore.LIGHTGREEN_EX} █")
    print(f"{Fore.LIGHTGREEN_EX}\t{'=' * 73}")
    print("\n")
    print(Style.RESET_ALL)


def write_to_csv(writer, csvdata=None, heading=0):
    """
    Function that writes to output csv file
    :param csvdata: ssllab dict containing the data to be written
    :param heading: settin it to 1 writes the csv file header
    :return: None
    """
    try:
        if heading:
            writer.writeheader()
        else:
            writer.writerow(csvdata)
    except Exception as e:
        LOGGER.error(e, exc_info=True)


def decode_certificate(pem_cert):
    with threadLock:
        file = f"temp_{random.randint(0, 10000000)}.crt"
        with open(file, 'w') as f:
            f.write(pem_cert)
        decoded = ssl._ssl._test_decode_cert(file)
        if os.path.exists(file):
            os.remove(file)
        return decoded


def parse_certificate(cert_dict, certificate, cert_len):
    try:
        cert_decode = decode_certificate(certificate)
        # x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
        # for value in cert_decode.get('subject'):
        cert_dict['Subject'] = str(cert_decode.get('subject')) or "Err"
        cert_dict['Issuer'] = str(cert_decode.get('issuer')) or "Err"
        cert_dict['Issued To'] = str(cert_decode['subject'][-1][-1][-1]) \
            if "commonName" in cert_decode['subject'][-1][-1][0] else "Err"
        cert_dict['Serial Num'] = str(cert_decode.get('serialNumber')) or "Err"
        cert_dict['Version'] = str(cert_decode.get('version')) or "Err"
        if cert_decode.get('subjectAltName'):
            cert_dict['Subject Alternative Names'] = ",".join(san[-1]
                                                              for san in cert_decode.get('subjectAltName')) or "Err"
        cert_dict['Valid From'] = cert_decode.get('notBefore')
        cert_dict['Valid To'] = cert_decode.get('notAfter')
        cert_dict['OCSP'] = cert_decode.get('OCSP')[0] if cert_decode.get('OCSP') else "No OCSP Found"

        # check if cert is expired
        valid_from = datetime.datetime.strptime(cert_dict['Valid From'], '%b %d %H:%M:%S %Y %Z')
        valid_to = datetime.datetime.strptime(cert_dict['Valid To'], '%b %d %H:%M:%S %Y %Z')
        today = datetime.datetime.today()
        if (valid_to - today).days >= 0 and (today - valid_from).days >= 0 and (valid_to - valid_from).days >= 0:
            cert_dict['Expired'] = "N"
            if (valid_to - today).days < 10:
                cert_dict['Expire Soon'] = "Y"
            else:
                cert_dict['Expire Soon'] = "N"
        else:
            cert_dict['Expired'] = "Y"

        # check if cert is self signed
        if cert_dict['Subject'] == cert_dict['Issuer'] and cert_len == 1:
            cert_dict['Self Signed'] = "Y"
        else:
            cert_dict['Self Signed'] = "N"
    except Exception as e:
        LOGGER.error(e, exc_info=True)
        error_dict(cert_dict, status="Error decoding certificate")


def build_ocsp_reqest(pem_cert, pem_issuer):
    try:
        cert = load_pem_x509_certificate(pem_cert)
        issuer = load_pem_x509_certificate(pem_issuer)
        builder = ocsp.OCSPRequestBuilder()
        # SHA1 is in this example because RFC 5019 mandates its use.
        builder = builder.add_certificate(cert, issuer, SHA1())
        req = builder.build()
        # print(req)
        return req.public_bytes(serialization.Encoding.DER)
    except Exception as e:
        LOGGER.error(e, exc_info=True)
        return None


def error_dict(cert_dict, status="", comments=""):
    do_not_write = ['Hostname', "Status", "PTR/A Record", "Comments"]
    if status:
        cert_dict['Status'] = status
    if comments:
        cert_dict['Comments'] = comments
    for key in Certificate_Dict.keys():
        if key not in do_not_write:
            cert_dict[key] = "Err"


def find_PTR_A_recrd(app,recrd_type="A"):
    try:
        if recrd_type == "PTR":
            name, alias, addresslist = socket.gethostbyaddr(app)
            return name
        else:
            ipaddr = socket.gethostbyname(app)
            return ipaddr
    except Exception as e:
        return "Err"


def get_certs(cert_dict, hostname, port=443):
    """
    This function connects to the host and downloads the entire certificate chain.
    :param cert_dict: a dictionary that keeps the certificate info
    :param hostname: the host to connect to
    :param port: port running https
    :return: a list containing all the certificates in order, starting from client cert to root cert
    """
    # Most supported TLS method is SSL.SSLv23_METHOD. But some servers like google reject this.
    # So we have to move to a different TLS method
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        protocols = [ssl.PROTOCOL_TLS]
        for protocol in protocols:
            s.settimeout(10)
            s.connect((hostname, port))
            context = ssl.SSLContext(protocol=protocol)
            ssl_socket = context.wrap_socket(s, server_hostname=hostname)
            ssl_socket.settimeout(10)
            ssl_socket.setblocking(True)
            cert_chain = ssl_socket.get_unverified_chain(binary_form=True)
            certs = [ssl.DER_cert_to_PEM_cert(cert) for cert in cert_chain]
            return certs
    except socket.timeout:
        cert_dict['Status'] = "Timed out"
        return None
    except TimeoutError:
        cert_dict['Status'] = "Timed out"
        return None
    except ConnectionResetError:
        cert_dict['Status'] = "Conn Reset"
        return None
    except ConnectionRefusedError:
        cert_dict['Status'] = "Conn Refused"
        return None
    except ConnectionAbortedError:
        cert_dict['Status'] = "Conn Aborted"
        return None
    except ConnectionError:
        cert_dict['Status'] = "Conn Err"
        return None
    except ssl.SSLError:
        cert_dict['Status'] = "SSL Err"
        return None
    except Exception as e:
        cert_dict['Status'] = "Err"
        LOGGER.error(f"{str(e)} {hostname}", exc_info=True)
        return None


def cert_check(hostname, writer, port=443):
    global COMPLETE
    cert_dict = dict(Certificate_Dict)
    cert_dict['Hostname'] = hostname
    try:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            cert_dict['PTR/A Record'] = find_PTR_A_recrd(hostname, 'PTR')
        else:
            cert_dict['PTR/A Record'] = find_PTR_A_recrd(hostname)
    except Exception as e:
        LOGGER.error(f"{e}  {hostname}")
        cert_dict['PTR/A Record'] = "Err"
    try:
        ocsp_tries = 3
        while ocsp_tries:
            certs = get_certs(cert_dict,hostname, port=port)
            if certs:
                parse_certificate(cert_dict, certs[0], len(certs))
                ocsp_url = cert_dict.get('OCSP')
                if len(certs) > 1 and ocsp_url and ocsp_url != "Err" and ocsp_url != "No OCSP Found":
                    try:
                        data = build_ocsp_reqest(certs[0].encode(), certs[1].encode())
                        if data:
                            response = requests.post(ocsp_url,
                                                 headers={'Content-Type': 'application/ocsp-request'},
                                                 data=data, timeout=20)
                            ocsp_resp = ocsp.load_der_ocsp_response(response.content)
                            cert_dict['Revocation Status'] = str(ocsp_resp.certificate_status)
                            break
                        else:
                            cert_dict['Status'] = "OCSP Error"
                            cert_dict['Revocation Status'] = "OCSP Error"
                            ocsp_tries -= 1
                    except ValueError:
                        cert_dict['Status'] = "OCSP Failed"
                        cert_dict['Revocation Status'] = "OCSP Failed"
                        ocsp_tries -= 1
                    except Exception as e:
                        LOGGER.error(f"{hostname}  {e}", exc_info=True)
                        cert_dict['Status'] = "OCSP Error"
                        cert_dict['Revocation Status'] = "OCSP Error"
                        ocsp_tries -= 1
                elif len(certs) == 1:
                    cert_dict['Status'] = "Peer cert only"
                    cert_dict['Revocation Status'] = "OCSP Skipped"
                    break
                else:
                    cert_dict['Status'] = "No OCSP Found"
                    cert_dict['Revocation Status'] = "No OCSP Found"
                    break
            else:
                error_dict(cert_dict, status=cert_dict.get('Status') or "No TLS/SSL Certificate")
                break
    except Exception as e:
        LOGGER.error(f"{e}  {hostname}")
    with threadLock:
        write_to_csv(writer, cert_dict)
        COMPLETE += 1


def parse_arguments():
    """
    https://stackoverflow.com/questions/24180527/argparse-required-arguments-listed-under-optional-arguments
    :return: Parser Namespace
    """
    from argparse import ArgumentParser
    parser = ArgumentParser()
    optional_args = parser._action_groups.pop()
    required_args = parser.add_argument_group('required arguments')
    required_args.add_argument('-i', '--input', help='The input file with list of URLs', required=True)
    required_args.add_argument('-o', '--output', help='Output csv file', required=True)

    #  Optional Arguments
    optional_args.add_argument('-t', '--threads', help='Set the number of threads', required=False)
    parser._action_groups.append(optional_args)
    return parser.parse_args()


def create_task_generator(apps, writer):
    """
    A lazy generator to save memory. It will give the url tasks one by one to main without keeping everything in memory
    :apps: the list of urls to create task for
    :writer: a csv file to write output to
    :return: function that can be called to get the url output
    """
    for app in apps:
        def inner(app=app):
            return cert_check(app, writer)
        yield inner


def main():
    """
    Main function that calls everything.
    :return: None
    """
    global THREADS
    start_time = str(datetime.datetime.now())
    try:
        welcome()  # Prints welcome message
        cli_args = parse_arguments()
        if cli_args.threads:
            THREADS = int(cli_args.threads)
        print(f"{Fore.WHITE}[+] {Fore.LIGHTRED_EX}Loading URLS. Please Wait...{Fore.RESET}")
        # Count no of apps
        with open(cli_args.input) as f:
            for total_count, l in enumerate(f):
                pass
        total_count += 1
        print(f'[+] {total_count} URLS Loaded\n')

        csv_file = open(cli_args.output, mode='w', newline='')
        fieldnames = list(Certificate_Dict.keys())
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        write_to_csv(writer, heading=1)

        app_file = open(cli_args.input, 'r')
        start = time.time()
    except Exception as e:
        csv_file.close()
        LOGGER.error(e)
        print(f"{Fore.RED}[-] Critical Error.\n{e}\n[-] Exiting....\n")
        sys.exit(-1)

    #------------------------------------------------
    # Threadpool executor that launches the task
    # inspired by https://alexwlchan.net/2019/10/adventures-with-concurrent-futures/
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        try:
            futures_set = set()
            apps_list = [app.strip() for app in app_file.readlines()]
            task_generator = create_task_generator(apps_list, writer)
            for task in itertools.islice(task_generator, THREADS + 2):
                futures_obj = pool.submit(task)
                futures_set.add(futures_obj)

            while futures_set:
                done, futures_set = concurrent.futures.wait(futures_set, return_when=concurrent.futures.FIRST_COMPLETED,
                                                            timeout=300)
                time_elapsed = time.time()-start
                eta = (time_elapsed/ (COMPLETE or 1)) * (total_count - COMPLETE)
                status = f" {Fore.LIGHTRED_EX}{time_elapsed:{.2}f} Elapsed  {Fore.LIGHTGREEN_EX}{eta:{.2}f} ETA"
                log.print_status(COMPLETE, total_count, text=status)

                # Schedule the next set of futures.  We don't want more than N futures
                # in the pool at a time, to keep memory consumption down.
                for task in itertools.islice(task_generator, len(done)):
                    futures_obj = pool.submit(task)
                    futures_set.add(futures_obj)

        except (KeyboardInterrupt, SystemExit):
            print(f'{Fore.LIGHTBLUE_EX}\n!!!!{Fore.RED} Received keyboard interrupt,{Fore.LIGHTRED_EX} '
                  f'Quitting threads and {Fore.LIGHTGREEN_EX}Cleaning Up {Fore.LIGHTBLUE_EX}!!!!\n{Fore.RESET}')
            pool.shutdown(wait=False)
            sys.exit()
        except Exception as e:
            LOGGER.critical(f"------Critical error in main thread ------{e}", exc_info=True)
        finally:
            csv_file.close()
    log.print_status(COMPLETE, total_count, text=f"{' '*40}")
    end_time = time.time() - start
    print(f"\n[+] Scan complete in {Fore.LIGHTGREEN_EX}{end_time:{.2}f} seconds")


if __name__ == "__main__":
    main()
