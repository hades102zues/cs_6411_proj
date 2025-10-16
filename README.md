
> [!warning]
> You will **need** API keys from Malware Balzaar and Virus Total to run these scripts.

# get_sample.py 
Pulls virus samples from Malware Balzaar and stores in 
- malware_hashes.json

# discover_virus_total.py 
Takes the hashes in malware_hashes.json and submits them to Virus Total to identify their behavioural patterns. At the end, it produces:
- virus_total_info.json: a collection of all of the various samples and behavioural data
- tactic_info.json: a unique list of all tactics identified in our sample set
- technique_info.json: a unique list of all techniques identified in our sample set

# analyze_sample.py 
Pulls from virus_total_info.jso and sets up a one-hot encoded matrix with:
- columns: technique IDs
- rows: encoding vectors