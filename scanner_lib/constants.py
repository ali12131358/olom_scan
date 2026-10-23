MAX_TARGETS = 65536

SERVICE_NAMES={21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",139:"NetBIOS",443:"HTTPS",445:"SMB",587:"SMTP Submission",993:"IMAPS",995:"POP3S",1723:"PPTP",3306:"MySQL",3389:"RDP",5900:"VNC",8080:"HTTP Proxy",8291:"Winbox",8728:"RouterOS API",8729:"RouterOS API-SSL"}
def service_name(port): return SERVICE_NAMES.get(port,"Unknown service")
