
> [!warning]
> You will **need** API keys from Malware Balzaar and Virus Total to run these scripts.

# get_sample.py 
Pulls virus samples from Malware Balzaar and stores in 
- vault/malware_hashes.json

# discover_virus_total.py 
Takes the hashes in malware_hashes.json and submits them to Virus Total to identify their behavioural patterns. At the end, it produces:
- vault/virus_total_info.json: a collection of all of the various samples and behavioural data
- vault/tactic_info.json: a unique list of all tactics identified in our sample set
- vault/technique_info.json: a unique list of all techniques identified in our sample set
- cluster_tactic_info.json: lists info on the top 3 tatics per cluster
- vault/cluster_technique_info.json: lists info on the top 5 techniques per cluster

# analyze_sample.py 
Pulls from virus_total_info.json and sets up a one-hot encoded matrix with:
- columns: technique IDs
- rows: encoding vectors