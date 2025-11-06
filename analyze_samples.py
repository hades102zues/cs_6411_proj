import os
import json
import pandas as pd
from pathlib import Path
from sklearn.metrics import pairwise_distances
from sklearn_extra.cluster import KMedoids


def check_for_virustotal_db(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            virus_total_sample_db = json.load(f)
        return virus_total_sample_db
    else: 
        print("WARNING VIRUS TOTAL DB DOES NOT EXIST!")
        return {}
    
def check_for_tatics_db(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            tatics_db = json.load(f)
        return tatics_db
    else: 
        print("WARNING TATICS DB DOES NOT EXIST!")
        return {}
    
def check_for_techn_db(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            techn_db = json.load(f)
        return techn_db
    else: 
        print("WARNING TECHNIQUES DB DOES NOT EXIST!")
        return {}


def cluster_data(tatics_lookup_db, 
                 techn_lookup_db, 
                 sample_families,
                 one_hot_technique_matrix, 
                 cluster_top_techniques_file,
                 cluster_top_tactics_file):
    
    num_clusters = 4
    num_tactics = 3
    num_techns = 5


    # remove the families to prevent bias
    pairwise_df = one_hot_technique_matrix.drop(columns=sample_families, errors="ignore")
    
    # compute the jaccard distances
    jaccard = pairwise_distances(pairwise_df.to_numpy(), metric="jaccard")

    # Run K-Medoids
    kmed = KMedoids(n_clusters=num_clusters, metric="precomputed", random_state=42)
    kmed.fit(jaccard)

    # Add back our cluster labels
    one_hot_technique_matrix["cluster"] = kmed.labels_


##==== cluster tactics
    # determine the Tatics columns present in the matrix
    tactic_cols = [col for col in one_hot_technique_matrix.columns if col.startswith("TA")]

    # group by on the cluster value and then get a mean for each Tactic in the cluster
    cluster_tactic_profiles = one_hot_technique_matrix.groupby("cluster")[tactic_cols].mean()

    cluster_name = {} # stores names in csv
    cluster_tactics = {} # collects items in the code

    for c in cluster_tactic_profiles.index:
        # rotate so now each cluster index is the column
        # each row is a tatic and the value amount under each cluster column
        # grab the top 3 tactics per cluster
        top_tactics_per_cluster = cluster_tactic_profiles.T.nlargest(num_tactics, c)

        # convert the IDs to names and store them
        named_tatics = [tatics_lookup_db.get(ta, ta) for ta in top_tactics_per_cluster.index]
        cluster_name[c] = " + ".join(named_tatics)

        cluster_tactics[c] = {}
        cluster_tactics[c]["id"] = top_tactics_per_cluster.index.to_list()
        cluster_tactics[c]["name"] = named_tatics
   
    # send the data to the csv
    one_hot_technique_matrix["cluster_name"] = one_hot_technique_matrix["cluster"].map(cluster_name)
    one_hot_technique_matrix.to_csv("./vault/one_hot_matrix.csv", index=False)

    with open(cluster_top_tactics_file, "w") as f:
        json.dump(cluster_tactics, f, indent=2)


#=====cluster top 5 techniques
    # determine the technique columns present in the matrix
    techn_cols = [col for col in one_hot_technique_matrix.columns if col.startswith("T1")]

    # group by on the cluster value and then get a mean for each techniques in the cluster
    cluster_techn_profiles = one_hot_technique_matrix.groupby("cluster")[techn_cols].mean()


    
    cluster_techniques = {}

    for c in cluster_techn_profiles.index:
        top_techn_per_cluster = cluster_techn_profiles.T.nlargest(num_techns, c)
        named_techniques = [techn_lookup_db.get(tech, tech) for tech in top_techn_per_cluster.index]
        cluster_techniques[c] = {}
        cluster_techniques[c]["id"] = top_techn_per_cluster.index.to_list()
        cluster_techniques[c]["name"] = named_techniques
    
    # save samples to file
    with open(cluster_top_techniques_file, "w") as f:
        json.dump(cluster_techniques, f, indent=2)

    return [cluster_tactics, cluster_techniques]
    

def main():
    virus_total_file = Path("vault") / "virus_total_info.json"
    tatics_name_file = Path("vault") / "tactic_info.json"
    techn_name_file = Path("vault") / "technique_info.json"
    cluster_top_techniques_file = Path("vault") / "cluster_technique_info.json"
    cluster_top_tactics_file = Path("vault") / "cluster_tactic_info.json"

    virus_total_lookup_db = check_for_virustotal_db(virus_total_file)
    tatics_lookup_db = check_for_tatics_db(tatics_name_file)
    techn_lookup_db = check_for_techn_db(techn_name_file)

    if len(virus_total_lookup_db) < 1:
        print("***YOU HAVE NO VIRUS TOTAL DATA***")
        return 0
    
    sample_hashes = []
    sample_traits = []
    sample_families = []
    temp = set()

    for virus_hash, info in virus_total_lookup_db.items():
        sample_hashes.append(virus_hash)

        # Combine family name + tactics + with the list of techniques
        combined_traits = [info["family"]] + info["tactic_ids"]+info["flattened_technique_ids"]
        sample_traits.append(combined_traits)
        temp.add(info["family"])

       
    data = {
        "sample": sample_hashes,
        "traits": sample_traits
    }
    sample_families = list(temp)

    # loading a dataframe
    df = pd.DataFrame(data)

    # setup for one-hot encoding matrix
    one_hot_technique_matrix = df.explode("traits")\
        .assign(positive = 1) \
        .pivot(index="sample", columns="traits", values="positive") \
        .fillna(0).astype(int)
    
    # this will arrange each row in order of occurenence within sample_hashes.
    one_hot_technique_matrix = one_hot_technique_matrix.reindex(sample_hashes)

    # save our dataframe to file
    matrix_file = Path("vault") / "one_hot_matrix.csv"
    one_hot_technique_matrix.to_csv(matrix_file, index=False)


    # [ list(top_3_tactics), list(top_5_techniques) ]
    cluster_info = cluster_data(tatics_lookup_db, 
                 techn_lookup_db, 
                 sample_families, 
                 one_hot_technique_matrix, 
                 cluster_top_techniques_file,
                 cluster_top_tactics_file)


    

    
if __name__ == "__main__":
    main()