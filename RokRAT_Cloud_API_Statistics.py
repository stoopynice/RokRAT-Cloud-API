import requests
import csv
import time

api_key = "{virustotal_api_key}"
headers = {"x-apikey": api_key}

contacted_services_count = {
    "googleapis.com": 0,
    "graph.microsoft.com/v1.0/me/drive": 0,
    "api.dropboxapi.com": 0,
    "api.box.com": 0,
    "api.pcloud.com": 0,
    "cloud-api.yandex.net": 0,
    "mediafire.com/api": 0
}

def write_hash_to_csv(hash_val, writer):
    writer.writerow([hash_val])

def write_contacted_urls_to_csv(hash_val, contacted_urls, writer):
    writer.writerow([hash_val] + list(contacted_urls))

def update_contacted_services_count(contacted_urls):
    for service in contacted_services_count.keys():
        if any(service in url for url in contacted_urls):
            contacted_services_count[service] += 1

with open("RokRAT_hash.csv", "r") as csvfile:
    reader = csv.reader(csvfile)
    #next(reader)  # Skip the header row

    with open("RokRAT_Contacted_URL.csv", "w", newline="") as cloud_csvfile:
        cloud_writer = csv.writer(cloud_csvfile)
        cloud_writer.writerow(["Hash", "Contacted URLs"])

        for hash_row in reader:
            hash_val = hash_row[0]
            print(f"Processing hash: {hash_val}")
            contacted_urls = set()

            url = f"https://www.virustotal.com/api/v3/files/{hash_val}/contacted_urls"
            response = requests.get(url, headers=headers)
            data = response.json()

            if "data" in data:
                for entry in data["data"]:
                    if "attributes" in entry and "url" in entry["attributes"]:
                        url = entry["attributes"]["url"]
                        contacted_urls.add(url)

                write_contacted_urls_to_csv(hash_val, contacted_urls, cloud_writer)
                update_contacted_services_count(contacted_urls)
            else:
                print("No results found.")

            time.sleep(15)  # Sleep for 15 seconds to respect the rate limit

    print("Processing complete.")

# Write contacted services count to a separate file
with open("RokRAT_Cloud_API_Statistics.csv", "w", newline="") as count_csvfile:
    count_writer = csv.writer(count_csvfile)
    count_writer.writerow(["URL", "Count"])

    for service, count in contacted_services_count.items():
        count_writer.writerow([service, count])

print("Counts saved to RokRAT_Cloud_API_Statistics.csv.")
