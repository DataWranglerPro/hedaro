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
        
        for s in source:
            if s == 'sublist3r':
                out.append(self._obj.kali.get_sublist3r(column))
            elif s == 'amass':
                out.append(self._obj.kali.get_amass(column))

        # combine output and drop duplicates (keep first subdomain found)
        df = pd.concat(out, ignore_index=True).drop_duplicates('subdomain', keep='first', ignore_index=True)          
        
        return df    