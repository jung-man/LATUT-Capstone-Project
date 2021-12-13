from colorama import Fore, Back, Style
import csv
import re
from terminaltables import SingleTable

class Table:
    def __init__(self):
        self.data = [
    ['IP', 'Domain' , 'Vulnerability']
    ]

    def table_csv(self):
        regexOfDomain = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
        regexOfCVE = "CVE-\d{4}-\d{4,7}"

        ex1 = open('test.csv')
        ex1 = csv.reader(ex1)
        list_IP = []
        list_domain = []
        list_CVE = []
        for i in ex1:
            list_IP.append(str(i[0]))
            list_domain.append(str(i[1]))
            list_CVE.append(str(i[2]))

        # ## Get ip
        lisOf_ip = []
        for x in list_IP:
            lisOf_ip.append(x)

        # Get representatives of CVE
        repre_cve = []
        for cve in list_CVE:
            com_cve = re.findall(regexOfCVE,cve)
            if cve == " ":
                repre_cve.append(" ")
            else:
                repre_cve.append(com_cve[0:2])
                
        # Get representatives of domain
        first_domain = []
        
        for domain in list_domain:
            com_domain = re.findall(regexOfDomain,domain)      
            if com_domain == "[]" or com_domain == " ":
                first_domain.append(" ")
            else:
                first_domain.append(com_domain[0:2])
                                            
        # Put first elements of api to table
        for i in range(0,len(lisOf_ip)):
            self.data.append([lisOf_ip[i],first_domain[i],repre_cve[i]])

        table = SingleTable(self.data)
        print(Fore.GREEN)
        print(table.table)
