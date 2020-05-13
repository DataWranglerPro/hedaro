## hedaro
   
[![Latest PyPI version](https://img.shields.io/pypi/v/hedaro.svg)](https://pypi.python.org/pypi/hedaro) 
[![Latest Travis CI build status](https://api.travis-ci.org/hedaro-project/hedaro.png)](https://travis-ci.org/github/hedaro-project/hedaro) 

A pentesting library for Python

## Main Features
  - Built on top of Pandas
  - Get subdomains and run nmap scans with just a few lines of code
  
## Where to get it
The source code is currently hosted on GitHub at:
https://github.com/hedaro-project/hedaro

```sh
pip install hedaro
```  

## Dependencies
- Kali Linux (install Anaconda, py3)

## Usage

```sh
import pandas as pd
import hedaro as hd

# create df with target domain (make sure you have written permission to perform a pentest for the url below)
df = pd.DataFrame({'domain':['www.url.com']})

# get subdomains
sd = df.kali.get_subdomains('domain')

# run nmap
nm = df.kali.get_nmap(p_cmd = '-sV -p-', column = 'subdomain')

# run dirb
dirb = df.kali.get_dirb('subdomain')

# run nikto
nikto = df.kali.get_nikto(ports_col = 'port', hosts_col = 'subdomain')
```  

## Licence
The MIT License (MIT)

## Authors
**hedaro** was written by [David Rojas](david@hedaro.com)
