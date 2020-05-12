import pandas as pd
import subprocess
import re
import os

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

@pd.api.extensions.register_dataframe_accessor("kali")
class KaliAccessor:
    """ holds all target domains and ip4 numbers """
    def __init__(self, pandas_obj):
        self._validate(pandas_obj)
        self._obj = pandas_obj
         
    @staticmethod
    def _validate(obj):
        # verify there is a column of dtype object
        if obj.select_dtypes(include=['object']).size == 0:
            raise AttributeError("Must have a column of type string.")            
                   
    def _copy_d(self):
        """ make a copy of data """
        return Targets(data=self.data.copy())

    def get_sublist3r(self, column):
        """
        run sublist3r on list of domains

        Runs sublist3r on user provided domains

        Parameters
        ----------
        column : str
            column containing list of domains

        Returns
        -------
        dataframe
            cleaned up subdomains

        Examples
        --------
        Run sublist3r directly
        
        >>> import pandas as pd
        >>> import hedaro as hd
        >>> df = pd.DataFrame({'domain':['boozt.com']})
        >>> sl = df.kali.get_sublist3r(column='domain') 
        
        Run amass and feed its results back into sublist3r
        
        >>> import pandas as pd
        >>> import hedaro as hd
        >>> df = pd.DataFrame({'domain':['boozt.com']})
        >>> sl1 = df.kali.get_sublist3r(column='domain')  
        >>> sl2 = sl1.kali.get_sublist3r(column='subdomain')          
        """      
        out = []

        # get domains
        domains = self._obj.drop_duplicates(column, keep='first', ignore_index=True)[column]
        
        # call sublist3r for each domain
        for d in domains:
            cmd = ['sublist3r', '-d', d]     
            stdout = _run_in_shell(cmd)

            # ignore text prior to actual subdomains found by sublist3r
            n = len(stdout.splitlines())
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

        if len(out) > 0:
            # create df
            df = pd.DataFrame(out).drop_duplicates(ignore_index=True)
            df.columns = ['subdomain', 'domain']

            # add source and date
            df['source'] = 'sublist3r'
            df['add_dt'] = pd.to_datetime('today').date()
        else:
            # create df
            df = pd.DataFrame(columns = ['subdomain', 'domain'])          

        return df

    def get_amass(self, column):
        """
        run amass on list of domains

        Runs amass on user provided domains

        Parameters
        ----------
        column : str
            column containing list of domains

        Returns
        -------
        dataframe
            cleaned up subdomains

        Examples
        --------
        
        Run amass directly
        
        >>> import pandas as pd
        >>> import hedaro as hd
        >>> df = pd.DataFrame({'domain':['boozt.com']})
        >>> am = df.kali.get_amass(column='domain') 
        
        Run amass and feed its results back into amass
        
        >>> import pandas as pd
        >>> import hedaro as hd
        >>> df = pd.DataFrame({'domain':['boozt.com']})
        >>> am1 = df.kali.get_amass(column='domain')  
        >>> am2 = am1.kali.get_amass(column='subdomain')  
        """   
        out = []
        
        # get domains
        domains = self._obj.drop_duplicates(column, keep='first', ignore_index=True)[column]       

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
                    out.append((_escape_ansi(line2), d))
                    
        if len(out) > 0:
            # create df
            df = pd.DataFrame(out).drop_duplicates(ignore_index=True)
            df.columns = ['subdomain', 'domain']

            # add source and date
            df['source'] = 'amass'
            df['add_dt'] = pd.to_datetime('today').date()
        else:
            # create df
            df = pd.DataFrame(columns = ['subdomain', 'domain'])          

        return df   

    def get_subdomains(self, column, source=['sublist3r', 'amass']):
        """
        get subdomains on list of domains 

        Gets subdomains from provided list of domains using popular pentesting libraries

        Parameters
        ----------
        column : str
            column containing list of domains
        source : list
            list of pententing libraries to use. By default all are selected.
            default value = ['sublist3r', 'amass']

        Returns
        -------
        dataframe
            domains along with input domain, date, and source

        Examples
        --------
        >>> import pandas as pd
        >>> import hedaro as hd
        >>> df = pd.DataFrame({'domain':['boozt.com']})
        >>> sd = df.kali.get_subdomains(column='domain')  
        """      
        out = []
        
        # loop through each source
        for s in source:
            if s == 'sublist3r':
                out.append(self._obj.kali.get_sublist3r(column))
            elif s == 'amass':
                out.append(self._obj.kali.get_amass(column))

        # combine output and drop duplicates (keep first subdomain found)
        df = pd.concat(out, ignore_index=True).drop_duplicates('subdomain', keep='first', ignore_index=True)          
        
        return df    
    
    def get_subdomains_recursive(self, column, source=['sublist3r', 'amass']):
        """
        Recursive run on get_subdomains
        
        function will keep feeding subdomains found against sublist3r/amass until no new subdomains are found. Warning: This may take a long time.
        
        Parameters
        ----------
        column : str
            column containing list of domains
        source : list
            list of pententing libraries to use. By default all are selected.
            default value = ['sublist3r', 'amass']            

        Returns
        -------
        dataframe
            domains along with input domain, date, and source

        Examples
        --------
        >>> import pandas as pd
        >>> import hedaro as hd
        >>> df = pd.DataFrame({'domain':['boozt.com']})
        >>> sd = df.kali.get_subdomains_recursive(column='domain')        
        """
        # create history df
        hist = self._obj.kali.get_subdomains(column, source=source)

        # initialize variables
        flag = 1
        first_pass = True
        
        # loop until no new subdomains are found
        while flag > 0:
            if first_pass:
                # get subdomains
                current = hist.kali.get_subdomains('subdomain', source=source)  
                
                # add new subdomains to history
                hist = pd.concat([hist, current]).drop_duplicates('subdomain', keep='first', ignore_index=True)  
                
                # count the number of subdomains found
                flag = current.count()[0]
                
                # only run this code once
                first_pass = False
            else:    
                # filter out history domains
                mask = current['subdomain'].isin(hist['subdomain'])
                
                # if new subdomains are found
                if current[~mask].count()[0] > 0:
                    # get subdomains using only the new ones recently found
                    current = current[~mask].kali.get_subdomains(column='subdomain', source=source) 
                    
                    # update history
                    hist = pd.concat([hist, current]).drop_duplicates('subdomain', keep='first', ignore_index=True) 
                    
                    # count the number of subdomains found
                    flag = current.count()[0] 
                else:
                    # count the number of new subdomains found
                    flag = current[~mask].count()[0] 

        return hist    
    
    def get_nmap(self, p_cmd, column):
        """
        Run nmap on selected targets 

        Parameters
        ----------
        p_cmd : str
            user provided nmap commands
        column : str
            column containing list of targets

        Returns
        -------
        dataframe
            selected nmap output

        Examples
        --------
        >>> import pandas as pd
        >>> import hedaro as hd
        >>> df = pd.DataFrame({'domain':['boozt.com']})
        >>> nm = df.kali.get_nmap(p_cmd='-F -A', column='domain')  
        """    
        # get domains or ip4s
        hosts = self._obj.drop_duplicates(column, keep='first', ignore_index=True)[column]

        # call nmap and export to xml
        cmd = ['nmap'] + p_cmd.split() + ['-oX', '/tmp/tmp_nmap.txt'] + hosts.tolist()
        stdout = _run_in_shell(cmd) 
        
        # get and parse xml
        xml = self._get_nmap_xml_output()
        out = self._parse_nmap_xml(xml)

        return out    
    
    def _get_nmap_xml_output(self):  
        """ create xml object """
        import xml.etree.cElementTree as et
        
        try:
            # create xml object
            tree = et.parse('/tmp/tmp_nmap.txt')
            root = tree.getroot() 
        except et.ParseError:
            xml = '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE nmaprun>
            <?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
            <!-- Nmap 7.80 scan initiated Tue May  5 11:56:46 2020 as: nmap -F -oX /tmp/tmp_nmap.txt boozt.com -->
            <nmaprun scanner="nmap" args="nmap -F -oX /tmp/tmp_nmap.txt boozt.com" start="1588694206" startstr="Tue May  5 11:56:46 2020" version="7.80" xmloutputversion="1.04">
            <scaninfo type="syn" protocol="tcp" numservices="100" services="7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"/>
            <verbose level="0"/>
            <debugging level="0"/>
            <host starttime="1588694206" endtime="1588694208"><status state="up" reason="syn-ack" reason_ttl="54"/>
            </host>
            <runstats><finished time="1588694208" timestr="Tue May  5 11:56:48 2020" elapsed="2.13" summary="Nmap done at Tue May  5 11:56:48 2020; 1 IP address (1 host up) scanned in 2.13 seconds" exit="success"/><hosts up="1" down="0" total="1"/>
            </runstats>
            </nmaprun>'''
            # create fake xml object if there is a parse fail
            root = et.fromstring(xml)
        
        return root
    
    def _parse_nmap_xml(self, root):
        """ parse xml object """
     
        out = []
        
        # grab main xml tag
        hosts = root.findall('host')
        
        # loop through xml object
        for host in hosts:

            try:
                # get ip
                ip_num = host.findall('address')[0].attrib['addr']
            except:
                ip_num = ""
                
            try:
                # get host name
                host_name = host.findall('hostnames')[0].findall('hostname')[0].attrib['name']
            except:
                host_name = ""              
                
            try:
                # get os name
                os_name = host.findall('os')[0].findall('osmatch')[0].attrib['name']
            except:
                os_name = ""

            try:
                # get all ports
                ports = host.findall('ports')[0].findall('port')
                
                # loop through all ports
                for port in ports:
                    
                    try:
                        # get protocol
                        port_proto = port.attrib['protocol']
                    except:
                        port_proto = ""    
                        
                    try:
                        # get port status
                        port_state = port.findall('state')[0].attrib['state']
                    except:
                        port_state = ""                           

                    try:
                        # get port number
                        port_num = port.attrib['portid']
                    except:
                        port_num = ""  
                        
                    try:
                        # get service name
                        service_name = port.findall('service')[0].attrib['name']
                    except:
                        service_name = ""                          

                    try:
                        # get service product
                        service_product = port.findall('service')[0].attrib['product']
                    except:
                        service_product = ""   
                        
                    try:
                        # get service version
                        service_version = port.findall('service')[0].attrib['servicefp'].split(":")[1].split("%")[0].replace("V=","")
                    except:
                        service_version = ""                           
                        
                    try:
                        # get service finger print
                        service_fp = port.findall('service')[0].attrib['servicefp']
                    except:
                        service_fp = ""
                        
                    try:
                        # get script id
                        script_id = port.findall('script')[0].attrib['id']
                    except:
                        script_id = ""
                        
                    try:
                        # get script output
                        script_output = port.findall('script')[0].attrib['output']
                    except:
                        script_output = ""

                    # store data
                    out.append((ip_num, host_name, os_name, port_proto, port_state, port_num, service_name, service_product, service_version, service_fp, script_id, script_output))

            # on error
            except:
                out.append((ip_num, host_name, os_name, None, None, None, None, None, None, None, None, None))
                
            # make df
            cols = ['ip_num', 'host_name', 'os_name', 'port_proto', 'port_state', 'port_num', 'service_name', 'service_product', 'service_version', 'service_fp', 'script_id', 'script_output']
            df = pd.DataFrame(out, columns = cols)
            
        return df 
    
    def get_nikto(self, ports_col, hosts_col):
        """
        Run nikto on selected targets 

        Parameters
        ----------
        ports_col : str
            column containing list of ports
        hosts_col : str
            column containing list of targets            

        Returns
        -------
        dataframe
            selected nikto output

        Examples
        --------
        >>> import pandas as pd
        >>> import hedaro as hd
        >>> df = pd.DataFrame({'domain':['boozt.com','booztlet.com'], 'ports':[80, 1]})
        >>> nm = df.kali.get_nikto(ports_col='ports', hosts_col='domain')  
        """         
        
        # output
        out = []        

        for h in self._obj.loc[:,[hosts_col, ports_col]].itertuples():
            # call nikto and export to xml
            #nikto -h 104.16.152.195 -p 8080,8443 -o /tmp/tmp_nikto.txt -Format xml
            cmd = ['nikto'] + ['-h',h[1]] + ['-p', str(h[2])] + ['-o', '/tmp/tmp_nikto.txt', '-Format', 'xml']
            stdout = _run_in_shell(cmd) 

            # get and parse xml
            xml = self._get_nikto_xml_output('/tmp/tmp_nikto.txt')
            out.append(self._parse_nikto_xml(xml))
            
            try:
                # remove file if it exists
                # nikto appends to existing file, so we need to remove file with rm before running script
                os.remove('/tmp/tmp_nikto.txt')
            except OSError:
                pass              
            
        # combine output
        df = pd.concat(out)             

        return df.dropna(how='all')        
    
    def _get_nikto_xml_output(self, filename):  
        """ create xml object """
        import xml.etree.cElementTree as et      
        
        try:
            # create xml object
            tree = et.parse(filename)
            root = tree.getroot() 
        except (et.ParseError,FileNotFoundError):
            xml = '''<?xml version="1.0" ?>
            <!DOCTYPE niktoscan SYSTEM "/var/lib/nikto/docs/nikto.dtd">
            <niktoscan>
            <niktoscan hoststest="0" options="-h 104.16.152.195 -p 8080,8443 -o /tmp/tmp_nikto.txt -Format xml" version="2.1.6" scanstart="Fri May  8 10:24:38 2020" scanend="Wed Dec 31 19:00:00 1969" scanelapsed=" seconds" nxmlversion="1.2">
            </niktoscan>
            </niktoscan>'''
            # create fake xml object if there is a parse fail
            root = et.fromstring(xml)
        
        return root    
    
    def _parse_nikto_xml(self, root):
        """ parse xml object """
        out = []
        
        # grab main xml tag
        hosts = root.findall('niktoscan')        
        
        for host in hosts:

            try:
                # get ip
                ip_num = host.findall('scandetails')[0].attrib['targetip']
            except:
                ip_num = None

            try:
                # get host name
                host_name = host.findall('scandetails')[0].attrib['targethostname']
            except:
                host_name = None    

            try:
                # get port number
                port_num = host.findall('scandetails')[0].attrib['targetport']
            except:
                port_num = None   

            try:
                # get banner
                banner = host.findall('scandetails')[0].attrib['targetbanner']
            except:
                banner = None  

            try:
                # get error count
                err_count = host.findall('scandetails')[0].attrib['errors']
            except:
                err_count = None 

            try:
                # get ssl ciphers
                ssl_ciphers = host.findall('scandetails')[0].findall('ssl')[0].attrib['ciphers']
            except:
                ssl_ciphers = None     

            try:
                # get ssl issuers
                ssl_issuers = host.findall('scandetails')[0].findall('ssl')[0].attrib['issuers']
            except:
                ssl_issuers = None  

            try:
                # get ssl info
                ssl_info = host.findall('scandetails')[0].findall('ssl')[0].attrib['info']
            except:
                ssl_info = None                  

            try:    
                for item in host.findall('scandetails')[0].findall('item'):
                    try:
                        # get item id
                        item_id = item.attrib['id']
                    except:
                        item_id = None  

                    try:
                        # get item osvdbid
                        item_osvdbid = item.attrib['osvdbid']
                    except:
                        item_osvdbid = None  

                    try:
                        # get item osvdblink
                        item_osvdblink = item.attrib['osvdblink']
                    except:
                        item_osvdblink = None    

                    try:
                        # get item method
                        item_method = item.attrib['method']
                    except:
                        item_method = None  

                    try:
                        # get item desc 
                        item_desc = item.findall('description')[0].text
                    except:
                        item_desc = None 

                    try:
                        # get item uri 
                        item_uri = item.findall('uri')[0].text
                    except:
                        item_uri = None 

                    try:
                        # get item namelink 
                        item_namelink = item.findall('namelink')[0].text
                    except:
                        item_namelink = None 

                    try:
                        # get item iplink 
                        item_iplink = item.findall('iplink')[0].text
                    except:
                        item_iplink = None             

                    out.append((ip_num, host_name, port_num, banner, err_count, ssl_ciphers, ssl_issuers, ssl_info, item_id, item_osvdbid, item_osvdblink, item_method, item_desc, item_uri, item_namelink, item_iplink))
            except:
                out.append((ip_num, host_name, port_num, banner, err_count, ssl_ciphers, ssl_issuers, ssl_info, None, None, None, None, None, None, None, None))

        # make df
        cols = ['ip_num', 'host_name', 'port_num', 'banner', 'err_count', 'ssl_ciphers', 'ssl_issuers', 'ssl_info', 'item_id', 'item_osvdbid', 'item_osvdblink', 'item_method', 'item_desc', 'item_uri', 'item_namelink', 'item_iplink']
        df = pd.DataFrame(out, columns = cols)
            
        return df    
    
    def get_dirb(self, column):
        """
        run dirb on list of domains

        Runs dirb on user provided domains

        Parameters
        ----------
        column : str
            column containing list of domains

        Returns
        -------
        dataframe
            identified urls with http status

        Examples
        --------
        >>> import pandas as pd
        >>> import hedaro as hd
        >>> df = pd.DataFrame({'domain':['boozt.com']})
        >>> urls = df.kali.get_dirb(column='domain')        
        """      
        out = []

        # get domains
        domains = self._obj.drop_duplicates(column, keep='first', ignore_index=True)[column]
        
        # call dirb for each domain
        for d in domains:
            cmd = ['dirb', 'https://' + d] 
            stdout = _run_in_shell(cmd)

            # clean up data
            # example: + https://www.boozt.com/js/dump/translations/.git/HEAD (CODE:301|SIZE:25748) 
            for x in stdout.splitlines():
                if '+ http' in x.decode():
                    pieces = x.decode().strip().split(" ")
                    code = pieces[2].strip('()').split("|")[0].split("CODE:")[1] 
                    out.append((pieces[1],code))

        if len(out) > 0:
            # create df
            df = pd.DataFrame(out).drop_duplicates(ignore_index=True)
            df.columns = ['subdomain', 'code']

            # add source and date
            df['source'] = 'dirb'
            df['add_dt'] = pd.to_datetime('today').date()
        else:
            # create df
            df = pd.DataFrame(columns = ['subdomain', 'code'])          

        return df    