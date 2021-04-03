from ci import ci_attack
from lfi import lfi_attack
from rfi import rfi_attack
print("------")
rfi_attack('http://192.168.190.159/vulnerabilities/fi/?page=include.php')
print("------")
ci_attack('http://192.168.190.159/vulnerabilities/exec/')
print("------")
lfi_attack('http://192.168.190.159/vulnerabilities/fi/?page=include.php','GET')