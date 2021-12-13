import shodan
import sys
import re
import csv
# from data_process import Table

class ShodanApi:
    def __init__(self, query, verify=False):
        self.query = query
        self.apiKey = "2S8w5hX9jIVlkXArUEyI0YwbjB8uFElM"
        
    def get_Infor(self):
        regexOfDomain = "(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
        regexOfCVE = "[^/=]CVE-\d{4}-\d{4,7}'"
        
        try:
        # Setup the api
            api = shodan.Shodan(self.apiKey)
            csvFileObj = open('test.csv', 'w', newline='')
            # Perform the search
            # api_complete = api.search(query='Exchange server country:"VN" port:"443"', page=1)
            api_complete = api.search(query=self.query, page=1)
            thisdict = {}
            for i in range(0,10):
                if api_complete['matches'] == "[]":
                    break
                else:
                    # api_complete = api.search(query='Exchange server country:"VN" port:"443"', page=1+i)
                    api_complete = api.search(query=self.query, page=1+i)
                    for service in api_complete['matches']:                        
                        # print("IP: ", service['ip_str'])
                        thisdict["IP"] = service['ip_str']

                        if str(service["domains"]) == "[]":
                            # print("Domain: " )
                            thisdict["Domain"] = " "
                        else:
                            domainName = re.findall(regexOfDomain,str(service['domains']))
                            thisdict["Domain"] = domainName
                            # print("Domain: ")
                            # for x in range(0, len(domainName)):
                            #     print(domainName[x])

                        if 'vulns' in service:
                            vulns = re.findall(regexOfCVE,str(service['vulns']))
                            thisdict["Vulns"] = vulns
                            # print("Vuln: ", vulns)
                        else:
                            thisdict["Vulns"] = " "
                        #     print("Not have vuln !!!")
                        # print("==========================")
                    
                        csvWriter = csv.writer(csvFileObj)
                        csvWriter.writerow([thisdict["IP"],thisdict["Domain"], thisdict["Vulns"]])
                        # csvWriter.writerow([thisdict["IP"]])
            csvFileObj.close()
            # input_csv(thisdict["Domain"], thisdict["IP"], thisdict["Vulns"])
        except Exception as e:
                print ('Error: %s' % e)
                sys.exit(1)