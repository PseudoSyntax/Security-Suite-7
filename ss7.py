#############################
#Author: Chicken
#Script: Security Suite 7
#Version: 1.3
#############################
import urllib.request
import re
import urllib3
import sys
from datetime import datetime as dt
import time
import requests
import json
import os
import json
import base64
import requests
import argparse
from urllib3.util import parse_url
import traceback
from tkinter.messagebox import showerror
if sys.version_info[0] == 3:
    import tkinter as tk
else:
    import Tkinter as tk

start = time.time()


# Create the parser
parser = argparse.ArgumentParser(prog='simple_printer',
                                usage='%(prog)s [options] integer string',
                                description='A Simple Program which prints to the Console',
                                prefix_chars='-')
 
parser = argparse.ArgumentParser()
parser.add_argument('-v', '--version', action='version',
                    version='%(prog)s 1.3.0')

# Add an integer argument
parser.add_argument('-f', '--flag', metavar='INT',
                    type=int, help='Debug Flag(Do Not Use)')
 
# Add a first string argument
parser.add_argument('-who', metavar='DOMAIN',
                    type=str, help='Generates WhoIs Record')

# Add a second string argument
parser.add_argument('-mx',  metavar='DOMAIN',
                    type=str, help='Generates MX/SPF Record')

# Add a third string argument
parser.add_argument('-vt', metavar='DOMAIN/SHA-256HASH',
                    type=str, help='Generates virus total Record')

parser.add_argument('-vtg',action='store_true' ,
                    help='Generates virus total GUI')

# Add a fourth string argument
parser.add_argument('-bl',  metavar='DOMAIN',
                    type=str, help='Checks via URL Void for blacklist on domain')

# Parse the list of arguments into an object
# called 'args'
args = parser.parse_args()

first_argument = args.flag
mx_arg_DOMAIN = args.mx
whois_arg_DOMAIN = args.who
vt_arg_DOMAIN = args.vt
vtg_GUI = args.vtg
blocklist_arg_DOMAIN = args.bl

# total arguments
n = len(sys.argv)
print("Total arguments passed:", n)


tableFormat = " {:6} {:12} {:34} {:50} "
mxtableFormat = " {:60} {:10} "

########################HEADERS###########################

vtg_headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "X-Tool": "vt-ui-main",
    "X-VT-Anti-Abuse-Header": "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNjMxMTE3NzQyLjY1",
    "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
}

headers = {
    'authority': 'mxtoolbox.com',
    'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
    'sec-ch-ua-mobile': '?0',
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
    'content-type': 'application/json; charset=utf-8',
    'accept': 'application/json, text/javascript, */*; q=0.01',
    'tempauthorization': '27eea1cd-e644-4b7b-bebe-38010f55dab3',
    'x-requested-with': 'XMLHttpRequest',
    'sec-ch-ua-platform': '"Linux"',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-mode': 'cors',
    'sec-fetch-dest': 'empty',
    'referer': 'https://mxtoolbox.com/SuperTool.aspx?action=mx%3a'+str(mx_arg_DOMAIN)+'&run=toolpage',
    'accept-language': 'en-US,en;q=0.9',
    'cookie': 'HttpOnly; HttpOnly; MxVisitorUID=6b4f683e-4c47-4ea8-b8fa-501f0148dc49; _mxt_s=anon; _mx_vtc=VWO-Blocked=true; ASP.NET_SessionId=5df3gpcr0vlfeavfurironcy; _mxt_u={"UserId":"00000000-0000-0000-0000-000000000000","UserName":null,"FirstName":null,"IsAdmin":false,"IsMasquerade":false,"IsPaidUser":false,"IsLoggedIn":false,"MxVisitorUid":"6b4f683e-4c47-4ea8-b8fa-501f0148dc49","TempAuthKey":"27eea1cd-e644-4b7b-bebe-38010f55dab3","IsPastDue":false,"BouncedEmailOn":null,"NumDomainHealthMonitors":0,"NumDisabledMonitors":0,"XID":null,"AGID":"00000000-0000-0000-0000-000000000000","Membership":{"MemberType":"Anonymous"},"CognitoSub":"00000000-0000-0000-0000-000000000000","HasBetaAccess":false,"IsOnTrial":false}; ki_r=; ki_t=1654875023356%3B1657553380336%3B1657553595189%3B5%3B18',
}

params = {
    'command': 'mx',
    'argument': str(mx_arg_DOMAIN),
    'resultIndex': '1',
    'disableRhsbl': 'true',
    'format': '2',
}
headers_spf = {
    'authority': 'mxtoolbox.com',
    'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="99", "Google Chrome";v="99"',
    'sec-ch-ua-mobile': '?0',
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36',
    'content-type': 'application/json; charset=utf-8',
    'accept': 'application/json, text/javascript, */*; q=0.01',
    'tempauthorization': '27eea1cd-e644-4b7b-bebe-38010f55dab3',
    'x-requested-with': 'XMLHttpRequest',
    'sec-ch-ua-platform': '"Linux"',
    'sec-fetch-site': 'same-origin',
    'sec-fetch-mode': 'cors',
    'sec-fetch-dest': 'empty',
    'referer': 'https://mxtoolbox.com/SuperTool.aspx?action=spf%3a'+str(mx_arg_DOMAIN)+'&run=toolpage',
    'accept-language': 'en-US,en;q=0.9',
    'cookie': 'HttpOnly; HttpOnly; MxVisitorUID=6b4f683e-4c47-4ea8-b8fa-501f0148dc49; _mxt_s=anon; _mx_vtc=VWO-Blocked=true; ASP.NET_SessionId=5df3gpcr0vlfeavfurironcy; _mxt_u={"UserId":"00000000-0000-0000-0000-000000000000","UserName":null,"FirstName":null,"IsAdmin":false,"IsMasquerade":false,"IsPaidUser":false,"IsLoggedIn":false,"MxVisitorUid":"6b4f683e-4c47-4ea8-b8fa-501f0148dc49","TempAuthKey":"27eea1cd-e644-4b7b-bebe-38010f55dab3","IsPastDue":false,"BouncedEmailOn":null,"NumDomainHealthMonitors":0,"NumDisabledMonitors":0,"XID":null,"AGID":"00000000-0000-0000-0000-000000000000","Membership":{"MemberType":"Anonymous"},"CognitoSub":"00000000-0000-0000-0000-000000000000","HasBetaAccess":false,"IsOnTrial":false}; ki_r=; ki_t=1654875023356%3B1657642971076%3B1657644280575%3B6%3B23',
}

params_spf = {
    'command': 'spf',
    'argument': str(mx_arg_DOMAIN),
    'resultIndex': '1',
    'disableRhsbl': 'true',
    'format': '2',
}


headers_whois = {
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Content-Type': 'application/json; charset=utf-8',
    'Cookie': 'HttpOnly; MxVisitorUID=e065f828-5605-4d40-9eb7-038cc13199ab; _ga=GA1.2.1160333303.1654624614; _vwo_uuid_v2=DB36FC4100003281FB8E15CC766A8ECB9|2c28ece3e9dbc5874dfab2d6f057cde9; _vis_opt_s=1%7C; _vwo_uuid=DB36FC4100003281FB8E15CC766A8ECB9; _vwo_ds=3%241654624613%3A61.32233608%3A%3A; _cioanonid=ee785a7f-175f-828d-2429-96be6336d060; _ce.s=v~ad791ff3b8e76dc9143025a5ef8c90fe9627ee29~vpv~0; _gaexp=GAX1.2.cxRGP203RIq2sNG52CHmdA.19225.2; HttpOnly; _mxt_u={"UserId":"00000000-0000-0000-0000-000000000000","UserName":null,"FirstName":null,"IsAdmin":false,"IsMasquerade":false,"IsPaidUser":false,"IsLoggedIn":false,"MxVisitorUid":"e065f828-5605-4d40-9eb7-038cc13199ab","TempAuthKey":"27eea1cd-e644-4b7b-bebe-38010f55dab3","IsPastDue":false,"BouncedEmailOn":null,"NumDomainHealthMonitors":0,"NumDisabledMonitors":0,"XID":null,"AGID":"00000000-0000-0000-0000-000000000000","Membership":{"MemberType":"Anonymous"},"CognitoSub":"00000000-0000-0000-0000-000000000000","HasBetaAccess":false,"IsOnTrial":false}; _mxt_s=anon; ki_r=; _mx_vtc=AB-586=Variation&VWO-Blocked=true; ASP.NET_SessionId=fzvuniyifckjaahijycmnvkw; ki_t=1654624613889%3B1657726948810%3B1657730201861%3B7%3B36',
    'Referer': 'https://mxtoolbox.com/SuperTool.aspx?action=whois%3a'+str(whois_arg_DOMAIN)+'&run=toolpage',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'TempAuthorization': '27eea1cd-e644-4b7b-bebe-38010f55dab3',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
    'X-Requested-With': 'XMLHttpRequest',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

params_whois = {
    'command': 'whois',
    'argument': str(whois_arg_DOMAIN),
    'resultIndex': '1',
    'disableRhsbl': 'true',
    'format': '2',
}

vt_headers = {
    "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "X-Tool": "vt-ui-main",
    "X-VT-Anti-Abuse-Header": "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNjMxMTE3NzQyLjY1",
    "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
}


headers_blocklist = {
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'keep-alive',
    'Content-Type': 'application/json; charset=utf-8',
    'Cookie': 'HttpOnly; MxVisitorUID=e065f828-5605-4d40-9eb7-038cc13199ab; _ga=GA1.2.1160333303.1654624614; _vwo_uuid_v2=DB36FC4100003281FB8E15CC766A8ECB9|2c28ece3e9dbc5874dfab2d6f057cde9; _vis_opt_s=1%7C; _vwo_uuid=DB36FC4100003281FB8E15CC766A8ECB9; _vwo_ds=3%241654624613%3A61.32233608%3A%3A; _cioanonid=ee785a7f-175f-828d-2429-96be6336d060; _ce.s=v~ad791ff3b8e76dc9143025a5ef8c90fe9627ee29~vpv~0; _gaexp=GAX1.2.cxRGP203RIq2sNG52CHmdA.19225.2; HttpOnly; _mxt_u={"UserId":"00000000-0000-0000-0000-000000000000","UserName":null,"FirstName":null,"IsAdmin":false,"IsMasquerade":false,"IsPaidUser":false,"IsLoggedIn":false,"MxVisitorUid":"e065f828-5605-4d40-9eb7-038cc13199ab","TempAuthKey":"27eea1cd-e644-4b7b-bebe-38010f55dab3","IsPastDue":false,"BouncedEmailOn":null,"NumDomainHealthMonitors":0,"NumDisabledMonitors":0,"XID":null,"AGID":"00000000-0000-0000-0000-000000000000","Membership":{"MemberType":"Anonymous"},"CognitoSub":"00000000-0000-0000-0000-000000000000","HasBetaAccess":false,"IsOnTrial":false}; _mxt_s=anon; ki_r=; _mx_vtc=AB-586=Variation&VWO-Blocked=true; ASP.NET_SessionId=fzvuniyifckjaahijycmnvkw; ki_t=1654624613889%3B1657726948810%3B1657730201861%3B7%3B36',
    'Referer': 'https://mxtoolbox.com/SuperTool.aspx?action=blocklist%3a'+str(blocklist_arg_DOMAIN)+'&run=toolpage',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'TempAuthorization': '27eea1cd-e644-4b7b-bebe-38010f55dab3',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36',
    'X-Requested-With': 'XMLHttpRequest',
    'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}

params_blocklist = {
    'command': 'blocklist',
    'argument': str(blocklist_arg_DOMAIN),
    'resultIndex': '1',
    'disableRhsbl': 'true',
    'format': '2',
}
#####################################################




########################MX###########################
response = requests.get('https://mxtoolbox.com/api/v1/Lookup', params=params, headers=headers)

# Convert data to dict
data1 = response.json()

# Convert dict to string
data = json.dumps(data1)

##tempFile.write(str(data))
mxResult = re.findall('Reported by <b>(.+?)</b> on', data)[0]
########################SPF###########################
response2 = requests.get('https://mxtoolbox.com/api/v1/Lookup', params=params_spf, headers=headers_spf)
data2 = response2.json()
dataSPF = json.dumps(data2)
spfResult = re.findall('Reported by <b>(.+?)</b> on', dataSPF)[0]
########################WHOIS###########################
response3 = requests.get('https://mxtoolbox.com/api/v1/Lookup', params=params_whois, headers=headers_whois)
data3 = response3.json()
dataWho = json.dumps(data3)
########################################################
response4 = requests.get('https://mxtoolbox.com/api/v1/Lookup', params=params_blocklist, headers=headers_blocklist)
data4 = response4.json()
dataBlock = json.dumps(data4)
########################################################

if mx_arg_DOMAIN:
     print("=====================================MX RESULTS======================================")
     print("Target: "+mx_arg_DOMAIN+"          Reporting Server: "+str(mxResult))
     print("=====================================================================================")
     print(" HOSTNAME                                                     IP ADDRESS ")
     try:
          for x in range(0,20):
               print(mxtableFormat.format(
                    re.findall('a:(.+?),', data)[x].replace("\\n","").replace("'",""),
                    re.findall('ptr:(.+?),', data)[x]).replace("\\n","").replace("'",""))
     except:
          print("=====================================================================================\n")

     print("=====================================SPF RESULTS======================================")
     print("Target: "+mx_arg_DOMAIN+"          Reporting Server: "+str(spfResult))
     print("=====================================================================================")
     print("PFX     TYPE         VALUE                              DESCRIPTION")

     print("        "+
          re.findall("Type'>(.+?)<", dataSPF)[0]
          +"             "+
          re.findall("Value'>(.+?)<", dataSPF)[0]+
          "                              "+
          re.findall("Description'>(.+?)<", dataSPF)[0])


     try:
          RgExp = re.findall('v=spf1(.+?)<', dataSPF)[0].split(" ")# Parse values into a list

          for z in range(0,20):

               print(tableFormat.format( 
                    re.findall("tr><tr><td class='table-column-Prefix'>(.+?)<", dataSPF)[z],

                    re.findall("Type'>(.+?)<", dataSPF)[z+1],

                    RgExp[z+1].replace("ip4:"," ").replace("ip6:"," ").replace("a:"," ").replace("include:"," ").replace("~all","").replace("redirect","")
                    .replace("=",""),

                    re.findall("-column-Description'>(.+?)<", dataSPF)[z+1]))
     except:
          print("=====================================================================================")

elif whois_arg_DOMAIN:
     print("======================WhoIs======================")
     try:
          RgExp = re.findall("Domain Name:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("Domain Name:" + temp)

          RgExp = re.findall("Registry Domain ID:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("Registry Domain ID:" + temp)

          RgExp = re.findall("Registrar WHOIS Server:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("Registrar WHOIS Server:" +temp)

          RgExp = re.findall("Registrar URL:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")

          print("Registrar URL: " + temp)

          RgExp = re.findall("Updated Date:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")

          print("Updated Date:" + temp)

          RgExp = re.findall("Creation Date:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")

          print("Creation Date: " + temp)

          RgExp = re.findall("Registry Expiry Date:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")

          print("Registry Expiry Date: " + temp) 

          RgExp = re.findall("Registrar:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("Registrar: "+temp)

          RgExp = re.findall("Registrar IANA ID:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("Registrar IANA ID: "+temp)

          RgExp = re.findall("Registrar Abuse Contact Email:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("Registrar Abuse Contact Email: "+temp)

          RgExp = re.findall("Registrar Abuse Contact Phone:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("Registrar Abuse Contact Phone: "+temp)

          RgExp = re.findall("Domain Status:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("Domain Status: "+temp)

          RgExp = re.findall("Domain Status:(.+?) ", dataWho)[1]
          temp = RgExp.replace("\\n" , "")
          print("Domain Status: "+temp)

          RgExp = re.findall("Domain Status:(.+?) ", dataWho)[2]
          temp = RgExp.replace("\\n" , "")
          print("Domain Status: "+temp)

          RgExp = re.findall("Name Server:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("Name Server: "+temp)

          RgExp = re.findall("Name Server:(.+?) ", dataWho)[1]
          temp = RgExp.replace("\\n" , "")
          print("Name Server: "+temp)

          RgExp = re.findall("Name Server:(.+?) ", dataWho)[2]
          temp = RgExp.replace("\\n" , "")
          print("Name Server: "+temp)

          RgExp = re.findall("Name Server:(.+?) ", dataWho)[3]
          temp = RgExp.replace("\\n" , "")
          print("Name Server: "+temp)

          RgExp = re.findall("DNSSEC:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("DNSSEC: "+temp)

          RgExp = re.findall("URL of the ICANN Whois Inaccuracy Complaint Form:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("URL of the ICANN Whois Inaccuracy Complaint Form: "+temp)

          RgExp = re.findall("Last update of whois database:(.+?) ", dataWho)[0]
          temp = RgExp.replace("\\n" , "")
          print("Last update of whois database: "+temp)
     except:
          print("Not in an acceptable format for terminal or records do not exist. Please check details here: \n" + "https://mxtoolbox.com/SuperTool.aspx?action=whois%3a"+str(whois_arg_DOMAIN)+"&run=toolpage")

elif vt_arg_DOMAIN:

    if "." in vt_arg_DOMAIN:
        response = requests.get('https://www.virustotal.com/ui/domains/' + str(vt_arg_DOMAIN), headers=vt_headers)
        vt_data = json.loads(response.content)


        malicious = vt_data['data']['attributes']['last_analysis_stats']['malicious']
        undetected = vt_data['data']['attributes']['last_analysis_stats']['undetected']
        harmless = vt_data['data']['attributes']['last_analysis_stats']['harmless']
        
        print(f'===DOMAIN RESULTS===\n Malicous Domain: {malicious}\n Undetected Domain: {undetected}\n Harmless Domain: {harmless}')
        print('\nhttps://www.virustotal.com/gui/domain/' + vt_arg_DOMAIN)
    
    elif "." not in vt_arg_DOMAIN:
          try:
               response = requests.get('https://www.virustotal.com/ui/files/' + vt_arg_DOMAIN, headers=vt_headers)
               vt_data = json.loads(response.content)


               malicious = vt_data['data']['attributes']['last_analysis_stats']['malicious']
               undetected = vt_data['data']['attributes']['last_analysis_stats']['undetected']
               harmless = vt_data['data']['attributes']['last_analysis_stats']['harmless'] 
               
               MD5 = vt_data['data']['attributes']['md5']
               SHA1 =vt_data['data']['attributes']['sha1']
               SHA256 =vt_data['data']['attributes']['sha256']
               Vhash =vt_data['data']['attributes']['vhash']
               Authentihash =vt_data['data']['attributes']['authentihash']
               Imphash =vt_data['data']['attributes']['pe_info']['imphash']
               Rich_PE_HeaderHash = vt_data['data']['attributes']['pe_info']['rich_pe_header_hash']
               SSDEEP =vt_data['data']['attributes']['ssdeep']
               TLSH =vt_data['data']['attributes']['tlsh']

               print(f'===HASH RESULTS===\n Malicous Hash: {malicious}\n Undetected Hash: {undetected}\n Harmless Hash: {harmless}')
                    
               print(f'\n===HASH VARIATIONS===\n MD5: {MD5}\n SHA1: {SHA1}\n SHA256: {SHA256}\n Vhash: {Vhash}\n Authentihash: {Authentihash}\n Imphash: {Imphash}\n Rich PE Header Hash: {Rich_PE_HeaderHash}\n SSDEEP: {SSDEEP}\n TLSH: {TLSH}')
               print('\nhttps://www.virustotal.com/gui/file/' + vt_arg_DOMAIN)
          except:
               print("An invalid SHA-256 hash was used or the hash was not in Virus Total's database")        
    else:
        print("Error not a valid domain or SHA-256 hash")


elif vtg_GUI:

     root= tk.Tk()

     url = "https://www.virustotal.com/ui/domain/bpwhamburgorchardpark.org"
     headers = {
         "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
         "X-Tool": "vt-ui-main",
         "X-VT-Anti-Abuse-Header": "MTA3OTM2NjUwMjctWkc5dWRDQmlaU0JsZG1scy0xNjMxMTE3NzQyLjY1",
         "Accept-Ianguage": "en-US,en;q=0.9,es;q=0.8",
     }

     root.title("No API Key Virus Total - API.py")
     root.geometry('450x400')
     #root['bg'] = '#ffbf00'

     canvas1 = tk.Canvas(root, width = 400, height = 300,  relief = 'raised')
     canvas1.pack()

     label1 = tk.Label(root, text='VirusTotal.com')
     label1.config(font=('helvetica', 14))
     canvas1.create_window(200, 45, window=label1)

     label11 = tk.Label(root, text='No API Used')
     label11.config(font=('helvetica', 10))
     canvas1.create_window(200, 500, window=label11)

     label2 = tk.Label(root, text='Type your Domain/Hash:')
     label2.config(font=('helvetica', 10))
     canvas1.create_window(200, 100, window=label2)

     entry1 = tk.Entry (root) 
     canvas1.create_window(200, 140, window=entry1)

     def getAction():
         
         x1 = entry1.get()


         URL_domain = x1

         response = requests.get('https://www.virustotal.com/ui/domains/' + URL_domain, headers=headers)
         data = json.loads(response.content)

         malicious = data['data']['attributes']['last_analysis_stats']['malicious']
         undetected = data['data']['attributes']['last_analysis_stats']['undetected']
         harmless = data['data']['attributes']['last_analysis_stats']['harmless']

         label_domain = tk.Label(root, text=f'Malicous Domain: {malicious}\n Undetected Domain: {undetected}\n Harmless Domain: {harmless}',font=('helvetica', 10, 'bold'))
         canvas1.create_window(200, 230, window=label_domain)


     def getAction2():
         
         x2 = entry1.get()


         hash_text = x2

         response = requests.get('https://www.virustotal.com/ui/files/' + hash_text, headers=headers)
         data = json.loads(response.content)

         try:
               response = requests.get('https://www.virustotal.com/ui/files/' + hash_text, headers=headers)
               vt_data = json.loads(response.content)

               malicious = vt_data['data']['attributes']['last_analysis_stats']['malicious']
               undetected = vt_data['data']['attributes']['last_analysis_stats']['undetected']
               harmless = vt_data['data']['attributes']['last_analysis_stats']['harmless'] 
               
               MD5 = vt_data['data']['attributes']['md5']
               SHA1 = vt_data['data']['attributes']['sha1']
               SHA256 =vt_data['data']['attributes']['sha256']
               Vhash =vt_data['data']['attributes']['vhash']
               Authentihash =vt_data['data']['attributes']['authentihash']
               Imphash =vt_data['data']['attributes']['pe_info']['imphash']
               Rich_PE_HeaderHash = vt_data['data']['attributes']['pe_info']['rich_pe_header_hash']
               SSDEEP =vt_data['data']['attributes']['ssdeep']
               TLSH =vt_data['data']['attributes']['tlsh']

               print(f'===HASH RESULTS===\n Malicous Hash: {malicious}\n Undetected Hash: {undetected}\n Harmless Hash: {harmless}')
                    
               print(f'\n===HASH VARIATIONS===\n MD5: {MD5}\n SHA1: {SHA1}\n SHA256: {SHA256}\n Vhash: {Vhash}\n Authentihash: {Authentihash}\n Imphash: {Imphash}\n Rich PE Header Hash: {Rich_PE_HeaderHash}\n SSDEEP: {SSDEEP}\n TLSH: {TLSH}')
               print('\nhttps://www.virustotal.com/gui/file/' + vt_arg_DOMAIN)
         except:
               print("An invalid SHA-256 hash was used or the hash was not in Virus Total's database")

         label_hash = tk.Label(root, text=f'Malicous Hash: {malicious}\n Undetected Hash: {undetected}\n Harmless Hash: {harmless}',font=('helvetica', 10, 'bold'))
         canvas1.create_window(200, 230, window=label_hash)

     button1 = tk.Button(text='Check Domain', command=getAction, bg='brown', fg='white', font=('helvetica', 9, 'bold'))
     canvas1.create_window(150, 180, window=button1)

     button2 = tk.Button(text='Check Hash', command=getAction2, bg='brown', fg='white', font=('helvetica', 9, 'bold'))
     canvas1.create_window(250, 180, window=button2)

     def show_error(self, *args):
         err = traceback.format_exception(*args)
         tkMessageBox.showerror('Exception',err)
     tk.Tk.report_callback_exception = show_error
     root.mainloop()

elif blocklist_arg_DOMAIN:
     Regx_IP = re.findall("resolves to <strong>(.+?)<", dataBlock)
     Regx_times = re.findall("Listed <strong>(.+?)<", dataBlock)
     Regx_timeout = re.findall("with <strong>(.+?)</strong> timeouts", dataBlock)
     if "" in Regx_timeout[0]:
          Regx_timeout[0] = "0"
     print("Checking " + str(blocklist_arg_DOMAIN) + " which resolves to ")
     print(str(Regx_IP[0]) + " against 91 known blocklist...")
     print("Listed " + str(Regx_times[0]) + " with " + str(Regx_timeout[0]) + " timeouts")
else:
     print("Use the --help or -h flag to see options")

###########LoadingTime###########
end = time.time()
eTime = end - start

if eTime > 60:
     timeType = "minutes"
else:
     timeType = "seconds"

print("\nElapsed Time: " + str(round(eTime,3)) + " " + timeType)
