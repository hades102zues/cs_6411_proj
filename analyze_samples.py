import os
import json
import pandas as pd
from pathlib import Path


def check_for_virustotal_db(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            virus_total_sample_db = json.load(f)
        return virus_total_sample_db
    else: 
        return {}
    
def main():
    virus_total_file = Path("vault") / "virus_total_info.json"
    virus_total_lookup_db = check_for_virustotal_db(virus_total_file)

    if len(virus_total_lookup_db) < 1:
        print("***YOU HAVE NO VIRUS TOTAL DATA***")
        return 0
    
    sample_hashes = []
    sample_techniques = []

    for virus_hash, info in virus_total_lookup_db.items():
        sample_hashes.append(virus_hash)
        sample_techniques.append(info["flattened_technique_ids"])
    
    data = {
        "sample": sample_hashes,
        "techniques": sample_techniques
    }

    # loading a dataframe
    df = pd.DataFrame(data)

    # setup for one-hot encoding matrix
    one_hot_technique_matrix = df.explode("techniques")\
        .assign(positive = 1) \
        .pivot(index="sample", columns="techniques", values="positive") \
        .fillna(0).astype(int)
    
    # this will arrange each row in order of occurenence within sample_hashes.
    one_hot_technique_matrix = one_hot_technique_matrix.reindex(sample_hashes)
    
    matrix_file = Path("vault") / "one_hot_matrix.csv"
    one_hot_technique_matrix.to_csv(matrix_file, index=False)
    

    # bunch of ml analysis techniques or whatever 
if __name__ == "__main__":
    main()