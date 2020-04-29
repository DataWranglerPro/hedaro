import pandas as pd
import subprocess
import re

def _escape_ansi(line):
    """
    clean up ugly text

    Removes extra characters sorounding a domain

    Parameters
    ----------
    line : str
        string value you want to clean up

    Returns
    -------
    str
        clean version of string
        
    Examples
    --------
    >>> str = '\x1Bwww.boozlet.com'
    >>> new_str = hd.escape_ansi(str)
    >>> new_str
       'www.boozlet.com'
        
    """    
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
    return ansi_escape.sub('', line)

def _run_in_shell(cmd):
    """
    run command in shell

    Runs shell code using the subprocess python module

    Parameters
    ----------
    cmd : list
        list containing the commands to run

    Returns
    -------
    str
        raw stdout from subprocess
        
    Examples
    --------
    >>> cmd = ['sublist3r', '-d', d]     
    >>> stdout = run_in_shell(cmd)
        
    """      
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=False)
    stdout, stderr = proc.communicate()

    return stdout

def get_sublist3r(self, column):
    """
    run sublist3r on list of domains

    Runs sublist3r on user provided domains

    Parameters
    ----------
    column : list
        column containing list of domains

    Returns
    -------
    class
        cleaned up subdomains

    Examples
    --------
    Run sublist3r directly

    >>> import hedaro as hd
    >>> t = hd.Targets(domain=['boozt.com'])
    >>> sl = t.get_sublist3r(column='domain')  

    Run sublist3r and feed its results back into sublist3r

    >>> import hedaro as hd
    >>> t = hd.Targets(domain=['boozt.com'])
    >>> sl = t.get_sublist3r(column='domain').get_sublist3r(column='subdomain')          
    """      
    out = []

    # make a copy
    mycopy = self._copy_d()

    # get domains
    domains = mycopy.data.drop_duplicates(column, keep='first', ignore_index=True)[column]

    # call sublist3r for each domain
    for d in domains:
        cmd = ['sublist3r', '-d', d]     
        stdout = _run_in_shell(cmd)

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
                out.append((_escape_ansi(line2), d))

        # create df
        df = pd.DataFrame(out).drop_duplicates(ignore_index=True)
        df.columns = ['subdomain', 'domain']

        # add source and date
        df['source'] = 'sublist3r'
        df['add_dt'] = pd.to_datetime('today').date()

        # place results into class
        mycopy.data = df

    return mycopy

def get_amass(domains):
    """
    run amass on list of domains

    Runs amass on user provided domains

    Parameters
    ----------
    domains : list
        list of domains

    Returns
    -------
    list
        cleaned up subdomains

    Examples
    --------

    Run amass directly

    >>> import hedaro as hd
    >>> t = hd.Targets(domain=['boozt.com'])
    >>> am = t.get_amass(column='domain')  

    Run amass and feed its results back into amass

    >>> import hedaro as hd
    >>> t = hd.Targets(domain=['boozt.com'])
    >>> am = t.get_amass(column='domain').get_amass(column='subdomain')           
    """   
    out = []     

    # call amass for each domain
    for d in domains:
        cmd = ['amass', 'enum', '--passive', '-d', d]     
        stdout = _run_in_shell(cmd)

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
                out.append(_escape_ansi(line2))        

    return out     

def get_subdomains(self, column, source=['sublist3r', 'amass']):
    """
    get subdomains on list of domains 

    Gets subdomains from provided list of domains using popular pentesting libraries

    Parameters
    ----------
    column : list
        column containing list of domains
    source : list
        list of pententing libraries to use. By default all are selected.
        default value = ['sublist3r', 'amass']

    Returns
    -------
    class
        domains along with input domain, date, and source

    Examples
    --------
    >>> import hedaro as hd
    >>> t = hd.Targets(domain=['boozt.com'])
    >>> sd = t.get_subdomains(column='domain')  
    """      
    out = []

    # make a copy
    mycopy = self._copy_d()

    for s in source:
        if s == 'sublist3r':
            out.append(self.get_sublist3r(column).data)
        elif s == 'amass':
            out.append(self.get_amass(column).data)

    # combine output and drop duplicates (keep first subdomain found)
    df = pd.concat(out, ignore_index=True).drop_duplicates('subdomain', keep='first', ignore_index=True)

    # place results into class
    mycopy.data = df              

    return mycopy    
    
