import shodan
import sys
import csv

class ShodanApi:
    def __init__(self, query, verify=False):
        self.query = query
        self.apiKey = "zLgu4WAgkwbCp5c7fVYOWm7q6lBMLWcn"
        
    def get_Infor(self):      
        try:
            # Setup the api
            api = shodan.Shodan(self.apiKey)
            csvFileObj = open('test.csv', 'w', newline='')
            csvWriter = csv.writer(csvFileObj)
            csvWriter.writerow(["IP", "Domain", "Vulns"])
            api_complete = api.search(query=self.query)
            # Perform the search
            for i in range(0,10):
                # api_complete = api.search(query=self.query, page=i)
                if api_complete['matches'] == None or api_complete['matches'] == []:
                    break
                else:
                    # data = []
                    api_complete = api.search(query=self.query, page=1+i)
                    for item in api_complete['matches']:
                        lst_vuln=[]
                        for i in item.get('vulns',{}).keys():
                            lst_vuln.append(i)
                        ip = item.get('ip_str', '')
                        domains = item.get('hostnames', '')
                        vulns = lst_vuln
                        csvWriter.writerow([ip,domains,vulns])                         
            csvFileObj.close()
        except shodan.APIError as e:
            pass
            # print ('Error: %s' % e)
