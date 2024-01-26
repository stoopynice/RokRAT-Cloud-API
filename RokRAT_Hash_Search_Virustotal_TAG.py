import requests
import csv
import time

api_key = "{virustotal_api_key}"
url = "https://www.virustotal.com/api/v3/search"
headers = {"x-apikey": api_key}

cursor = None

def write_hash_to_csv(hash_val, writer):
    writer.writerow([hash_val])

with open("RokRAT_hash.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)

    for _ in range(10):  # 10 iterations of requests will give us 100 results
        params = {
            "query": "rokrat",
            "limit": 1
        }
        
        if cursor:
            params['cursor'] = cursor
            
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        
        if 'data' in data:
            for result in data["data"]:
                if 'id' in result:
                    id_str = result['id']
                    hash_val = id_str.split('-')[1]
                    write_hash_to_csv(hash_val, writer)
            if 'meta' in data and 'cursor' in data['meta']:
                cursor = data['meta']['cursor']  # Update the cursor to the next page cursor
            else:
                break  # Break the loop if there is no 'cursor' in the response
        else:
            print("No results found.")
        
        # Sleep for 15 seconds to respect the rate limit of the free API (4 requests per minute)
        time.sleep(15)

    if not cursor:
        print("No more hashes to retrieve.")
    
    print("작업 완료!")
