import pandas as pd
import subprocess
import re

def escape_ansi(line):
    ''' clean up ugly text '''
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)

def run_in_shell(cmd):
    ''' run command in shell '''
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=False)
    stdout, stderr = proc.communicate()

    return stdout

def get_sublist3r(domains):
    ''' run sublist3r on list of domains '''
    out = []
    
    # call sublist3r for each domain
    for d in domains:
        cmd = ['sublist3r', '-d', d]     
        stdout = run_in_shell(cmd)
        
        # ignore text prior to actual subdomains found by sublist3r
        for x in stdout.splitlines():
            if 'Total Unique Subdomains Found:' in x.decode():
                # find location of text in list
                n = stdout.splitlines().index(x)     
                
        # list of subdomains
        subdomains = stdout.splitlines()[n+1:]

        # clean up data and store in out
        for line in subdomains:
            if not line:
                continue
            for line2 in line.decode().split('<BR>'):
                out.append((escape_ansi(line2), d))
                
        # create df
        df = pd.DataFrame(out).drop_duplicates(ignore_index=True)
        df.columns = ['subdomain', 'domain']
        
        # add source and date
        df['source'] = 'sublist3r'
        df['add_dt'] = pd.to_datetime('today').date()

    return df 

def get_amass(domains):
    ''' run amass on list of domains '''
    out = []
    
    # call amass for each domain
    for d in domains:
        cmd = ['amass', 'enum', '--passive', '-d', d]     
        stdout = run_in_shell(cmd)
        
        # ignore summary text at the end of amass run
        n = len(stdout.splitlines())
        for x in stdout.splitlines():
            if 'OWASP' in x.decode():
                # find location of text in list
                n = stdout.splitlines().index(x)  
                
        # list of subdomains
        subdomains = stdout.splitlines()[:n]                
                
        # clean up data and store in out
        for line in subdomains:
            if not line:
                continue
            # ignore amass logging  
            if 'Querying ' in line.decode():
                continue
            for line2 in line.decode().split('<BR>'):
                out.append((escape_ansi(line2), d))
                
        # create df
        df = pd.DataFrame(out).drop_duplicates(ignore_index=True)
        df.columns = ['subdomain', 'domain']
        
        # add source and date
        df['source'] = 'amass'
        df['add_dt'] = pd.to_datetime('today').date()

    return df     

def get_subdomains(domains, source=['sublist3r', 'amass']):
    ''' get subdomains on list of domains '''
    out = []
    for s in source:
        if s == 'sublist3r':
            out.append(get_sublist3r(domains))
        elif s == 'amass':
            out.append(get_amass(domains))

    # combine output and drop duplicates (keep first subdomain found)
    df = pd.concat(out, ignore_index=True).drop_duplicates('subdomain', keep='first', ignore_index=True)
    return df