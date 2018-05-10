#!/usr/bin/env python3
# Written By Marco Huang <marco@netq.co.nz>
# Date: 8 May 2018

from meraki import meraki
import sys
import csv
import datetime
import json
import requests

input_file='mrssidl3fwrules_input.csv'


def replace_ssid_l3fw_rules(api_key, api_id, ssid_name):
    fwrules=[]
    api_key=api_key
    api_id=api_id
    ssid_name=ssid_name

    with open(input_file) as csvfile:
        reader = csv.DictReader(csvfile)
                        
        for row in reader:
            csv_comment = row['comment']
            csv_policy = row['policy']
            csv_protocol = row['protocol']
            csv_destPort = row['destPort']
            csv_destCidr = row['destCidr']
            fwrules_data = [{'comment': csv_comment, 'policy': csv_policy, 'protocol': csv_protocol, 'destPort': csv_destPort, 'destCidr': csv_destCidr}]
            print(fwrules_data[0])
            fwrules.append(fwrules_data[0])

    resp=input('CAUTION! The existing firewall rules will be replaced. Do you want to add the above rules? [y|n]')
    while resp in ('y', 'n'):
        if resp == 'y':
            current_networks = meraki.getnetworklist(api_key, api_id,suppressprint=True)

            for network in current_networks:
                api_netid = network['id']
                api_netname = network['name']
                ssids = meraki.getssids(api_key, api_netid, suppressprint=True)
                if str(ssids) == 'None':
                    pass
                else:
                    ssid_num = len(ssids)

                    for num in range(0,ssid_num-1):
                        if ssids[num]['name'].startswith("Unconfigured SSID"):
                            pass
                        elif ssids[num]['name'].endswith(ssid_name):
                            print(network['name']+','+network['id']+','+ssids[num]['name'])
                            print(' ')
                            print(fwrules)
                            u_response=meraki.updatessidl3fwrules(api_key, network['id'], ssids[num], fwrules, allowlan=None, suppressprint=False)
                            print(u_response)
                            print('')
                            for rule_num in range(0,len(u_response)):
                                print(rule_num+1, u_response[rule_num])
                            print('')
            break
        else:
            break


def delete_ssid_l3fw_rules(api_key, api_id, ssid_name):
    api_key=api_key
    api_id=api_id
    ssid_name=ssid_name
    current_networks = meraki.getnetworklist(api_key, api_id,suppressprint=True)

    for network in current_networks:
        api_netid = network['id']
        ssids = meraki.getssids(api_key, api_netid, suppressprint=True)
        if str(ssids) == 'None':
            pass
        else:
            ssid_num = len(ssids)

            for num in range(0,ssid_num-1):
                if ssids[num]['name'].startswith("Unconfigured SSID"):
                    pass
                elif ssids[num]['name'].endswith("guru"):
                    print(network['name']+','+network['id']+','+ssids[num]['name'])
                    print(' ')

                    g_response=meraki.getssidl3fwrules(api_key, network['id'], ssids[num], suppressprint=False)
                    for rule_num in range(0,len(g_response)-1):
                        print(rule_num+1, g_response[rule_num])

                    is_valid=0
                    while not is_valid :
                        try :
                            r_num = int(input('Enter the rule number of the rule you would like to delete: '))
                            is_valid = 1 # set it to 1 to validate input and to terminate the while..not loop
                        except ValueError:
                            print ("'%s' Enter the rule number." % e.args[0].split(": ")[1])
                    del_num=r_num-1
                    del g_response[del_num]
                    fwrules=g_response[:-2]
                    print(fwrules)
                    u_response=meraki.updatessidl3fwrules(api_key, network['id'], ssids[num], fwrules, allowlan=None, suppressprint=False)
#                    print(u_response)
                    print('')
                    for rule_num in range(0,len(u_response)):
                        print(rule_num+1, u_response[rule_num])
                    print('')


def insert_ssid_l3fw_rules(api_key, api_id, ssid_name):
    api_key = api_key
    api_id = api_id
    ssid_name = ssid_name
    fwrules=[]

    with open(input_file) as csvfile:
        reader = csv.DictReader(csvfile)
                        
        for row in reader:
            csv_comment = row['comment']
            csv_policy = row['policy']
            csv_protocol = row['protocol']
            csv_destPort = row['destPort']
            csv_destCidr = row['destCidr']
            fwrules_data = [{'comment': csv_comment, 'policy': csv_policy, 'protocol': csv_protocol, 'destPort': csv_destPort, 'destCidr': csv_destCidr}]
            print(fwrules_data[0])
            fwrules.append(fwrules_data[0])

    resp=input('Do you want to insert the above rules? [y|n]')
    while resp in ('y', 'n'):
        if resp == 'y':

            resp_mode=input('Intert Rules at top? or Above the default rule? or interactive mode for each matched ssid? [t|b|i] ')
            current_networks = meraki.getnetworklist(api_key, api_id,suppressprint=True)

            for network in current_networks:
                api_netid = network['id']
                ssids = meraki.getssids(api_key, api_netid, suppressprint=True)
                if str(ssids) == 'None':
                    pass
                else:
                    ssid_num = len(ssids)

                    for num in range(0,ssid_num-1):
                        if ssids[num]['name'].startswith("Unconfigured SSID"):
                            pass
                        elif ssids[num]['name'].endswith(ssid_name):
                            print(network['name']+','+network['id']+','+ssids[num]['name'])
                            print(' ')

                            g_response=meraki.getssidl3fwrules(api_key, network['id'], ssids[num], suppressprint=False)
                            for rule_num in range(0,len(g_response)-2):
                                print(rule_num+1, g_response[rule_num])
                            print(' ')

                            if resp_mode == 't':
                                for r_num in range(0,len(fwrules)):
                                    g_response.insert(0, fwrules[r_num])
                            elif resp_mode == 'b':
                                for r_num in range(0,len(fwrules)):
                                    g_response.insert(len(g_response)-2, fwrules[r_num])
                            elif resp_mode == 'i':                                
                                is_valid=0
                                while not is_valid :
                                    try :
                                        insert_num = int(input('Enter the rule number of the rule you would like to insert BELOW: '))
                                        is_valid = 1 # set it to 1 to validate input and to terminate the while..not loop
                                    except ValueError:
                                        print ("'%s' Enter the rule number." % e.args[0].split(": ")[1])

                                for r_num in range(0,len(fwrules)):
                                    g_response.insert(insert_num, fwrules[r_num])
                            else:
                                print('Please start again!')
                                break

                            fwrules=g_response[:-2]
                            print(fwrules)
                            u_response=meraki.updatessidl3fwrules(api_key, network['id'], ssids[num], fwrules, allowlan=None, suppressprint=False)
                            print(u_response)
                            print('')
                            for rule_num in range(0,len(u_response)):
                                print(rule_num+1, u_response[rule_num])
                            print('')
            break
        else:
            break


def get_ssid_l3fw_rules(api_key, api_id, ssid_name):
    api_key=api_key
    api_id=api_id
    ssid_name=ssid_name

    current_networks = meraki.getnetworklist(api_key, api_id,suppressprint=True)

    for network in current_networks:
        api_netid = network['id']
        ssids = meraki.getssids(api_key, api_netid, suppressprint=True)
        if str(ssids) == 'None':
            pass
        else:
            ssid_num = len(ssids)

            for num in range(0,ssid_num-1):
                if ssids[num]['name'].startswith("Unconfigured SSID"):
                    pass
                elif ssids[num]['name'].endswith(ssid_name):
                    print(network['name']+','+network['id']+','+ssids[num]['name'])
                    print(' ')
                    g_response=meraki.getssidl3fwrules(api_key, api_netid, ssids[num], suppressprint=False)
                    print(g_response)
                    print('')
                    for rule_num in range(0,len(g_response)):
                        print(rule_num+1, g_response[rule_num])
                    print('')


def main():
    # Import API key and org ID from login.py
    try:
        import login
        (api_key, api_id, ssid_name) = (login.api_key, login.org_id, login.ssid_name)
    except ImportError:
        api_key = input('Enter your Dashboard API key: ')
        api_id = input('Enter your organization ID: ')

    print(33 * '-')
    print("   Meraki SSID L3FW MAIN MENU")
    print(33 * '-')
    print("1. Insert firewall rule")
    print("2. Delete firewall rule")
    print("3. Replace firewall rule")
    print("4. Get existing firewall rule")
    print("5. Exit")
    print(33 * '-')
     
    # Wait for valid input in while...not
    is_valid=0
     
    while not is_valid :
            try :
                    choice = int(input('Enter your choice [1-5] : '))
                    is_valid = 1 # set it to 1 to validate input and to terminate the while..not loop
            except ValueError:
                    print ("'%s' Use the option number listed." % e.args[0].split(": ")[1])

    # Take action as per selected menu-option
    if choice == 1:
        opt = 1
        print("Adding firewall rules to SSID ...")
        insert_ssid_l3fw_rules(api_key, api_id, ssid_name)
    elif choice == 2:
        opt = 2
        print("Searching for defined SSID ...")
        delete_ssid_l3fw_rules(api_key, api_id, ssid_name)
    elif choice == 3:
        opt = 3
        print("Inserting firweall rules ...")
        replace_ssid_l3fw_rules(api_key, api_id, ssid_name)
    elif choice == 4:
        opt = 4
        print("Getting firwall rules ...")
        get_ssid_l3fw_rules(api_key, api_id, ssid_name)
    elif choice == 5:
        opt = 5
        print("Bye...")
    else:
        print("Invalid input, try again...")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
