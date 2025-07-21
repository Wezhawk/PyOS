import requests
import os
import subprocess

print("Update helper started")
print("Preparing to download update...")

file_url = "https://raw.githubusercontent.com/Wezhawk/PyOS/main/update/PyOS.py"

try:
    print("Downloading file...")
    response = requests.get(file_url, stream=True)
    response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)

    with open("PyOS-update", 'wb') as file:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:  # Filter out keep-alive new chunks
                file.write(chunk)
    print(f"File '{"PyOS.py"}' downloaded successfully.")

except requests.exceptions.RequestException as e:
    print(f"Error downloading file: {e}")
    print("Update failed. Starting old file and quitting...")
    subprocess.run(["python", "PyOS.py"])
    exit()


print("Deleting old file...")
os.remove("PyOS.py")

print("Preparing to rename file...")
os.rename("PyOS-update", "PyOS.py")

print("Launching updated file...")
subprocess.run(["python", "PyOS.py", "updated"])

print("Update Completed")
print("Quitting")
exit()