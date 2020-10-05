#!/usr/bin/python3
import requests
import subprocess
import json
import re
import binascii
import hashlib
import base64
import time
import os
import sys
import pathlib

#import urllib3
#urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

contact_email="email@gmail.com" #letsecnrypt contact email
domain="ssh.mydomain.com" #letsencrypt issued certificate "name"
######CF
auth_email="cf_email@hotmail.com" #cloudflare email
auth_key="00000000000000000000000000" #cloudflare API Key
zone_name="mydomain.com" #cloudflare zone name
######CF
api="https://acme-v02.api.letsencrypt.org"
#api="https://acme-staging-v02.api.letsencrypt.org"#test_api
cf_headers = {
	'X-Auth-Email': auth_email,
	'X-Auth-Key'  : auth_key,
	'Content-Type': 'application/json',
}
acc_key="/etc/apache2/ssl/letsencrypt/acc.key"
acc_pub="/etc/apache2/ssl/letsencrypt/acc.pub"
dom_key="/etc/apache2/ssl/letsencrypt/"+domain+".key"
dom_pub="/etc/apache2/ssl/letsencrypt/"+domain+".pub"
dom_csr="/etc/apache2/ssl/letsencrypt/"+domain+".csr"
end_certificate="/etc/apache2/ssl/letsencrypt/"+domain+".crt"
jwk = None
jws_auth = None
jwk_thumbprint = None
proxies = {}
verify = True

def ossystem(c, stdinn=None, inputt=None, stdoutt=subprocess.PIPE):
	if(isinstance(c, str)):
		c = c.split(" ")
	if(stdoutt != subprocess.PIPE):
		stdoutt = open(stdoutt, 'w')
	proc = subprocess.Popen(c, stdin=stdinn, stdout=stdoutt, stderr=subprocess.PIPE)
	out, err = proc.communicate(inputt)
	if(stdoutt != subprocess.PIPE):
		stdoutt.close()
	return out

def _b64(b):
	return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")

def api_request(url,body=None):
	r = requests.get(api+"/acme/new-nonce", proxies=proxies, verify=verify)
	replay_nonce = r.headers['Replay-Nonce']
	if(api in jwk):
		header = {"url": url, "alg": "RS256", "nonce": replay_nonce, "kid": jwk}
	else:
		header = {"url": url, "alg": "RS256", "nonce": replay_nonce, "jwk": jwk}
	jws_protected = _b64(json.dumps(header).encode('utf8'))
	jws_payload = "" if body is None else _b64(json.dumps(body).encode('utf8'))
	jws_signature = "{0}.{1}".format(jws_protected, jws_payload).encode('utf8')
	jws_signature = _b64(ossystem("/bin/openssl dgst -sha256 -sign "+acc_key, subprocess.PIPE, jws_signature))
	jws = json.dumps({"protected": jws_protected, "payload": jws_payload, "signature": jws_signature})
	headers = {
		"content-Type": "application/jose+json",
	}
	r = requests.post(url, data=jws, headers=headers, proxies=proxies, verify=verify)
	return r

def cf_get_zone_id():
	url = "https://api.cloudflare.com/client/v4/zones?name={0}".format(zone_name)
	r = requests.get(url, headers=cf_headers, proxies=proxies, verify=verify)
	return json.loads(r.text)['result'][0]['id']

def cf_get_txt_record_id(zone_id, cfdomain):
	url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records?type=TXT&name={1}".format(zone_id, cfdomain)
	r = requests.get(url, headers=cf_headers, proxies=proxies, verify=verify)
	r = json.loads(r.text)
	if(len(r['result']) == 0):
		return False
	record_id = r['result'][0]['id']
	return record_id

def cf_create_txt_record(zone_id, cfdomain, key_auth):
	url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records".format(zone_id)
	payload = {
		'type': 'TXT',
		'name': cfdomain,
		'content': key_auth
	}
	r = requests.post(url, headers=cf_headers, json=payload, proxies=proxies, verify=verify)
	return json.loads(r.text)['result']['id']

def cf_delete_record(zone_id, record_id):
	url = "https://api.cloudflare.com/client/v4/zones/{0}/dns_records/{1}".format(zone_id, record_id)
	r = requests.delete(url, headers=cf_headers, proxies=proxies, verify=verify)

def delete_file(file):
	if os.path.exists(file):
		os.remove(file)

#subscriber agreement
r = requests.get(api+"/directory", proxies=proxies, verify=verify)

#creating a new account key for each certificate request
ossystem("/bin/openssl genrsa 4096", stdoutt=acc_key)
ossystem("/bin/openssl rsa -in "+acc_key+" -out "+acc_pub+" -pubout")
out = ossystem("/bin/openssl rsa -in "+acc_key+" -noout -text")
pub_pattern = r"modulus:[\s]+?00:([a-f0-9\:\s]+?)\npublicExponent: ([0-9]+)"
pub_hex, pub_exp = re.search(pub_pattern, out.decode('utf8'), re.MULTILINE|re.DOTALL).groups()
pub_exp = "{0:x}".format(int(pub_exp))
pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
alg = "RS256"
jwk = {
	"e": _b64(binascii.unhexlify(pub_exp.encode("utf-8"))),
	"kty": "RSA",
	"n": _b64(binascii.unhexlify(re.sub(r"(\s|:)", "", pub_hex).encode("utf-8"))),
}
jws_auth = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
jwk_thumbprint = _b64(hashlib.sha256(jws_auth.encode('utf8')).digest())

#register_account
r = api_request(api+"/acme/new-acct", { "termsOfServiceAgreed": True, "contact": [ "mailto:"+contact_email ] })
account_url = r.headers['Location']
jwk = account_url
#create domain
r = api_request(api+"/acme/new-order", { "identifiers": [{ "type": "dns", "value": domain }]})
order_url = r.headers['location']
r = json.loads(r.text)
order_finalize = r['finalize']
authorization_url = r['authorizations'][0]
r = api_request(authorization_url)
r = json.loads(r.text)['challenges']
for i in r:
	if(i['type'] == "dns-01"):
		chal_url = i['url']
		chal_token = i['token']
		break
keyAuthorization = chal_token+"."+jwk_thumbprint
key_auth=_b64(hashlib.sha256(keyAuthorization.encode('utf8')).digest())
cfdomain = domain
if (cfdomain[0:2] == "*."):
	cfdomain = cfdomain[2:]
cfdomain = "_acme-challenge."+cfdomain
zone_id = cf_get_zone_id()
search = cf_get_txt_record_id(zone_id, cfdomain)
if(search != False):
	cf_delete_record(zone_id, search)
record = cf_create_txt_record(zone_id, cfdomain, key_auth)
time.sleep(20)
r = api_request(chal_url)
r = api_request(chal_url,{"resource": "challenge","keyAuthorization": keyAuthorization})
while(True):
	r = api_request(chal_url)
	status = json.loads(r.text)['status']
	if(status != "pending"):
		break
	time.sleep(10)
cf_delete_record(zone_id, record)
if(status != "valid"):
	print("ERROR")
	print(r.text)
	print("restarting")
	time.sleep(20)
	os.system(pathlib.Path(__file__).absolute())
	sys.exit()
ossystem("/bin/openssl genrsa 4096", stdoutt=dom_key)
ossystem("/bin/openssl rsa -in "+dom_key+" -out "+dom_pub+" -pubout")
os.system('/bin/openssl req -new -sha256 -key '+dom_key+' -subj "/CN='+domain+'" -addext "subjectAltName=DNS:'+domain+'" > '+dom_csr)
csr = _b64(ossystem("/bin/openssl req -in "+dom_csr+" -outform DER"))
r = api_request(order_finalize, {"csr": csr})
certificate_url = json.loads(r.text)["certificate"]
certificate = api_request(certificate_url)
f = open(end_certificate, "w")
f.write(certificate.text)
f.close()
os.system("/sbin/service apache2 restart")
