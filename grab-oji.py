#! /usr/bin/env python3
import requests
import re
import os.path
import argparse
from hashlib import sha256

#----------------------------------------------------------------------
# This script downloads fresh samples of Android/Oji.G!worm
# Those APKs are MALWARE - DO NOT INSTALL THEM / PROPAGATE !
# You can then report them to your favorite malware database
# and report the malicious github account to GitHub
#
# Please handle with care
#
# May 7, 2021
#-----------------------------------------------------------------------

debug = True

# EDIT THIS LINK
url = 'hXXps://tiny.cc/COVID-VACCINE'

def debug_log(msg):
    if debug:
        print(msg)

def get_arguments():
    parser = argparse.ArgumentParser(description="Tool to download fresh Android/Oji worms. This tool is for malware analysts to retrieve new malware and add them to their favorite database for detection. Please beware. Note: not working first run? EDIT THE URL IN THE SCRIPT !")
    parser.add_argument('-g', '--github', help='download directly from GitHub repository', action='store')
    args = parser.parse_args()
    return args

def get_github(tiny_url):
    # The shortened link typically refers to a malicious github account        
    debug_log("[debug] Getting {}".format(url))        
    headers = { 'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1' }
    try:
        r = requests.get(url, headers=headers, allow_redirects=True, timeout=100)
        assert r.status_code == 200, "{} not reacheable".format(url)
    except requests.exceptions.InvalidSchema:
        print("Hey! You need to edit the URL in the Python script grab-oji.py !!!")
        quit()
        
    match = re.search(b'https://github.com/[a-zA-Z0-9]*/[a-zA-Z0-9]*/', r.content)
    assert match is not None, "No reference to github repos"

    github_repo = match.group(0)

    return github_repo

def download_from_github(github_repo):
    debug_log("[debug] Github_repo = {}".format(github_repo))
    g = requests.get(github_repo)
    assert g.status_code == 200, "Github {} not reacheable".format(github_repo)

    # We list the (malicious) apks from the github account
    repo_name = github_repo.replace(b'https://github.com/',b'')
    apks = re.findall(repo_name + b'.*[a-zA-Z0-9_].apk\"', g.content)
    debug_log("[debug] repo_name={} apks={}".format(repo_name, apks))
    print("[*] We should report to GitHub malicious account https://github.com/{}".format(repo_name.decode('utf-8')))
    
    # ... and dump each APK in a file
    for a in apks:
        apk_url = b'https://github.com/' + a[:-1]+b'?raw=true'
        debug_log("[debug] Getting APK: {}".format(apk_url))
        answer = requests.get(apk_url)
        assert answer.status_code == 200, "APK {} cannot be downloaded".format(apk_url)

        filename = sha256(answer.content).hexdigest()

        if os.path.exists(filename):
            print("[*] Filename {} is already present".format(filename))
        else:
            debug_log("[debug] Generating filename={}".format(filename))
            with open(filename, 'wb') as file:
                file.write(answer.content)
            print("[+] Dumped {} as {}".format(apk_url, filename))


if __name__ == "__main__":
    args = get_arguments()
    if args.github:
        download_from_github(bytes(args.github,'utf-8'))
    else:
        github_repo = get_github(url)
        download_from_github(github_repo)
                             
        






                    
                    
                    
                
                
