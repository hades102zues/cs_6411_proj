# This takes our malware hash samples and attempts to pull the information from Virus Total.
# You will need to sign up with Virus Total to receive an API Key.
# The free-tier is limited to 500 api calls.

import os
import json
import requests

def check_for_malwaare_db(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            virus_sample_db = json.load(f)
        return virus_sample_db
    else: 
        return {}
    
def check_for_virustotal_db(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            virus_total_sample_db = json.load(f)
        return virus_total_sample_db
    else: 
        return {}
    

def check_for_tactic_info(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            tactic_info = json.load(f)
        return tactic_info
    else: 
        return {}
    
def check_for_technique_info(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            technique_info = json.load(f)
        return technique_info
    else: 
        return {}



def pull_virus_total_info(tactic_storage, technique_storage, api_key, virus_hash, family):
    url = f"https://www.virustotal.com/api/v3/files/{virus_hash}/behaviour_mitre_trees"
    headerrs = {
        "accept": "accept: application/json",
        "x-apikey": api_key

    }
    res = requests.get(url,  headers=headerrs)

    # Check for success
    if res.status_code == 200:
        tactic_ids = []
        tactic_names = []
        techniques_names = []
        techniques_ids = []

        res_json = res.json()
        res_data = res_json.get("data")
        behavior_tree = ""

        if "Zenbox" in res_data:
            behavior_tree= "Zenbox"
        elif "CAPE Sandbox" in res_data:
            behavior_tree= "CAPE Sandbox"
        elif "Yomi Hunter" in res_data:
            behavior_tree= "Yomi Hunter"
        else:
            print(f"No behaviour tree found for sample: {virus_hash}")
            return (0, {})

        tactics = res_data.get(behavior_tree).get("tactics")
        flattened_technique_ids = []
        
        for tactic in tactics:
            tactic_ids.append(tactic["id"])
            tactic_names.append(tactic["name"])
            tactic_storage[tactic["id"]] = tactic["name"]

            store_techniques_ids = []
            store_techniques_names = []


            for tech in tactic.get("techniques", []):
                store_techniques_ids.append(tech["id"])
                store_techniques_names.append(tech["name"])
                flattened_technique_ids.append(tech["id"])
                technique_storage[tech["id"]] = tech["name"]
                

            techniques_names.append(store_techniques_names)
            techniques_ids.append(store_techniques_ids)

        flattened_technique_ids = list(set(flattened_technique_ids))  
        

        info = {
            "hash": virus_hash,
            "family": family,
            "flattened_technique_ids": flattened_technique_ids, # unique list of technique ids per tactic
           
            "tactic_ids": tactic_ids,
            "tactic_names": tactic_names,
            "techniques_ids": techniques_ids, # **NOTE a technique id can appear across multiple tactics.
            "techniques_names": techniques_names

        }
        return (1, info)
    else:
        print("Request failed.") 
        return (0, {})

def main():
    local_sample_file = "malware_hashes.json"
    sample_db= check_for_malwaare_db(local_sample_file)

    if len(sample_db) < 1:
        print("***YOU HAVE NO SAMPLES***")
        return 0


    api_key = input("Please supply Virus Total API KEY: ")
    virus_total_file = "virus_total_info.json"
    virus_total_lookup_db = check_for_virustotal_db(virus_total_file)

    tactics_file = "tactic_info.json"
    tactic_storage = check_for_tactic_info(tactics_file)
    techniques_file = "technique_info.json"
    technique_storage = check_for_technique_info(techniques_file)
    
    for virus_hash, sample in sample_db.items():
        # sample in the sample_db has already been retrieved
        # if sample["looked_up"] == "1":
        #     continue

        # sample's hash was already investigated.
        if virus_hash in virus_total_lookup_db:
            sample_db[virus_hash]["looked_up"] = "1"
            print("Sample already investidated")
            continue

        family = sample["family"]
        
        (looked_up, info) = pull_virus_total_info(tactic_storage, technique_storage, api_key, virus_hash, family)
        if looked_up == 1:
            virus_total_lookup_db[virus_hash]= info
            sample_db[virus_hash]["looked_up"] = "1"

        
    # save virus_total info to file
    with open(virus_total_file, "w") as f:
        json.dump(virus_total_lookup_db, f, indent=2)

    # resave sample_db
    with open(local_sample_file, "w") as f:
        json.dump(sample_db, f, indent=2)

    # save tactic info
    with open(tactics_file, "w") as f:
        json.dump(tactic_storage, f, indent=2)

    # save technique info
    with open(techniques_file, "w") as f:
        json.dump(technique_storage, f, indent=2)   

    print(f"Virus_Total DB count: {len(virus_total_lookup_db)}")

if __name__ == "__main__":
    main()