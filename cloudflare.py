#!/usr/bin/python3
import requests
import json
import re
import os
import sys
import subprocess
#import urllib3
#urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

######CF
auth_email="cf_email@gmail.com"
auth_key="00000000000000000000000000"
zone_name="mydomain.com"
######CF
interface = "ppp0"
proxies = {}
verify = True

cf_headers = {
	'X-Auth-Email': auth_email,
	'X-Auth-Key'  : auth_key,
	'Content-Type': 'application/json',
}

def ossystem(c):
	return subprocess.Popen(c, shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8").strip()

def getip(interface=interface):
	ipv4 = ossystem("/sbin/ifconfig "+interface+" | /bin/grep inet").strip().split(" ")[1]
	ipv6 = ossystem("/sbin/ifconfig "+interface+" | /bin/grep inet6").strip().split(" ")
	if(len(ipv6) > 1):
		ipv6 = ipv6[1]
	else:
		ipv6 = "0"

	return [ipv4, ipv6]

def cf_get_zone_id(zone_name=zone_name):
	url = "https://api.cloudflare.com/client/v4/zones?name={0}".format(zone_name)
	r = requests.get(url, headers=cf_headers, proxies=proxies, verify=verify)
	return json.loads(r.text)['result'][0]['id']

def cf_get_record(zone_id, cfdomain, type="A"):
	url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records?type={1}&name={2}".format(zone_id, type, cfdomain)
	r = requests.get(url, headers=cf_headers, proxies=proxies, verify=verify)
	r = json.loads(r.text)
	if(len(r['result']) == 0):
		return False
	return r['result']

def cf_get_all_records(zone_id):
	url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records".format(zone_id)
	r = requests.get(url, headers=cf_headers, proxies=proxies, verify=verify)
	r = json.loads(r.text)
	if(len(r['result']) == 0):
		return False
	return r['result']

def cf_create_record(zone_id, data): #={type,name,content,ttl,proxied}
	url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records".format(zone_id)
	r = requests.post(url, headers=cf_headers, json=data, proxies=proxies, verify=verify)
	return json.loads(r.text)['result']

def cf_update_record(zone_id, record_id, data): #={type,name,content,ttl,proxied}
	url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records/{1}".format(zone_id, record_id)
	r = requests.put(url, headers=cf_headers, json=data, proxies=proxies, verify=verify)
	return json.loads(r.text)['result']

def cf_delete_record(zone_id, record_id):
	url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records/{1}".format(zone_id, record_id)
	r = requests.delete(url, headers=cf_headers, proxies=proxies, verify=verify)
#data = {"type":,"name":,"content":,"ttl":,"proxied":}


my_ip = getip()
zone_id = cf_get_zone_id()
######################################################################################################
updateip = {
	"ssh.mydomain.com": {"type":"A","name":"ssh.mydomain.com","content":my_ip[0],"ttl":1,"proxied":False},
	"www.mydomain.com": {"type":"A","name":"www.mydomain.com","content":my_ip[0],"ttl":1,"proxied":True}
}


all_records = cf_get_all_records(zone_id)
for record in all_records:
	if(record['name'] in updateip and record['content'] != updateip[record['name']]['content']):
			cf_update_record(zone_id,record['id'],updateip[record['name']])
