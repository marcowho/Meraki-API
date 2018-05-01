#!/usr/bin/env python3

from meraki import meraki
import sys
import csv
import datetime


if __name__ == '__main__':
    # Import API key and org ID from login.py
    try:
        import login
        (api_key, api_id) = (login.api_key, login.org_id)
    except ImportError:
        api_key = input('Enter your Dashboard API key: ')
        api_id = input('Enter your organization ID: ')
    
    today = datetime.date.today()
    csv_file = open(login.org_name + '_' + str(today) + '.csv', 'w', encoding='utf-8')
    fieldnames = ['Network_Name', 'SSID_Name', 'PSK']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames, restval='')
    writer.writeheader()

    current_networks = meraki.getnetworklist(api_key, api_id,suppressprint=True)

    for network in current_networks:
#   	print(" ")
#   	print("NetworkName"+","+network['name'])
    	api_netid = network['id']
    	ssids = meraki.getssids(api_key, api_netid, suppressprint=True)
#    	print(len(ssids))
    	if str(ssids) == 'None':
#    		print("The network has no returned data")
    		pass
    	else:
    		ssid_num = len(ssids)



    		for num in range(0,ssid_num-1):
    			if ssids[num]['name'].startswith("Unconfigured SSID"):
    				pass
    			elif ssids[num]['authMode'] == 'psk':
    				print(network['name']+','+ssids[num]['name']+','+ssids[num]['psk'])
    				writer.writerow({'Network_Name': network['name'], 'SSID_Name': ssids[num]['name'], 'PSK': ssids[num]['psk']})
    			else:
    				print(network['name']+','+ssids[num]['name']+','+ssids[num]['authMode'])
    				writer.writerow({'Network_Name': network['name'], 'SSID_Name': ssids[num]['name'], 'PSK': ssids[num]['authMode']})
    csv_file.close()
