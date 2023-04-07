import requests  # pip install requests
import json  # pip install json
import re  # pip install re


def get_cve(cve):
    try:
        response = requests.get("https://cve.circl.lu/api/cve/%s" % (cve))
        response.raise_for_status()  # raise an exception if the response is not 200
        result = response.json()
        return json.dumps(result, indent=4)
    except:
        return 0
    try:
        return result[key]
    except:
        return 0


iplist = open("iplist.txt", "r")  # open the file with the list of IPs
Lines = iplist.readlines()  # read the lines of the file
output = open("info_output.json", "a")  # open the file to write the output
for line in Lines:
    pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")  # regex to match IPs
    lst = []
    lst.append(pattern.search(line)[0])  # append the IP to the list
    json_data = requests.get(
        "https://internetdb.shodan.io/" + lst[0]
    ).json()  # get the json data from the API
    print(json_data)  # print the json data
    output.write("\n .........This is info for IP Addess: " + lst[0] + "......\n")
    json.dump(json_data, output)  # write the json data to the file
    output.write("\n")  # write a new line to the file

    if json_data.get("vulns"):  # check if the key "vulns" exists in the json data
        for info in json_data.get("vulns"):
            print(get_cve(info))  # call the function to get the CVEs
            output.write(
                "\n Here is the info for the following CVE: "
                + info
                + "\n"
                + get_cve(info)
                + "\n"
            )  # write the CVE info to the file

iplist.close()  # close the file with the list of IPs
output.close()  # close the file to write the output
