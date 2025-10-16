# This file pulls malware samples from Malware Balzaar
# You will need to sign up and get an API key

import requests
import json
import os

def check_for_malwaare_db(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            virus_sample_db = json.load(f)
        return virus_sample_db
    else: 
        return {}
    
def download_samples(totals, virus_sample_db, api_key, malware_family, limit):
    body_data = {
        "query": "get_taginfo",
        "tag": malware_family,
        "limit": limit
    }
    url = "https://mb-api.abuse.ch/api/v1/"
    headerrs = {
        "Auth-Key": api_key
    }
    res = requests.post(url,  headers=headerrs, data=body_data)

    # Check for success
    if res.status_code == 200:
        result = res.json() 
        samples = result["data"]

        # record the samples
        for sample in samples:

            virus_hash = sample["sha256_hash"]
            strain = {
                "family": malware_family,
                "hash": virus_hash,
                "looked_up": "0"
                
            }
            virus_sample_db[virus_hash] = strain
            totals[malware_family] = totals[malware_family] + 1
        
    else:
        print("Error:", res.status_code, res.text)

def main():
    local_sample_file = "malware_hashes.json"
    virus_sample_db = check_for_malwaare_db(local_sample_file)
    auth_key = input("Please supply Malwaare Balzaar API KEY: ")

    mal_family = ["TrickBot", "Emotet", "AgentTesla", "QakBot", "LokiBot", "FormBook", "RedLineStealer", "Dridex"]
    sample_limit_per_family = 30

    totals = {}

    for family in mal_family:
        totals[family] = 0
        download_samples(totals, virus_sample_db, auth_key, family, sample_limit_per_family)

    # save samples to file
    with open(local_sample_file, "w") as f:
        json.dump(virus_sample_db, f, indent=2)

    print("=====Sample Totals")
    print(totals)
    




if __name__ == "__main__":
    main()