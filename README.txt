         .___    __________.__                        
       __| _/____\______   \  | _____  ________ ____  
      / __ |/ __ \|    |  _/  | \__  \ \___   // __ \ 
     / /_/ \  ___/|    |   \  |__/ __ \_/    /\  ___/ 
     \____ |\___  >______  /____(____  /_____ \___  >
          \/    \/       \/          \/      \/    \/ 
    jrose@owasp.org | jrose@trustwave.com | github.com/SpiderLabs

:warning: *NOTE: This tool is no longer under active maintenance.*

INTRODUCTION
============

Through the use of the Flex programming model and the ActionScript language,
Flash Remoting was born. Flash applications can make request to a remote server
to call server side functions, such as looking up accounts, retrieving
additional data and graphics, and performing complex business operations.
However, the ability to call remote methods also increases the attack surface
exposed by these applications.

This tool will allow you to perform method enumeration and interrogation
against flash remoting end points.  Deblaze came about as a necessity during a
few security assessments of flash based websites that made heavy use of flash
remoting. I needed something to give me the ability to dig a little deeper into
the technology and identify security holes.  On all of the servers I've seen so
far the names are not case sensitive, making it much easier to bruteforce.
Often times HTTP POST requests won't be logged by the server, so bruteforcing
may go unnoticed on poorly monitored systems.

Deblaze provides the following functionality: 
o Brute Force Service and Method Names
o Method Interrogation
o Flex Technology Fingerprinting


USAGE
=====

deblaze [option]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -u URL, --url=URL     URL for AMF Endpoint
  -s SERVICE, --service=SERVICE
                        Remote service to call
  -m METHOD, --method=METHOD
                        Method to call
  -p PARAMS, --params=PARAMS
                        Parameters to send pipe seperated
                        'param1|param2|param3'
  -c CREDS, --creds=CREDS
                        Username and password for service in u:p format
  -1 BRUTESERVICE, --bruteService=BRUTESERVICE
                        file to load services for brute forcing (mutually
                        exclusive to -s)
  -2 BRUTEMETHOD, --bruteMethod=BRUTEMETHOD
                        file to load methods for brute forcing (mutually
                        exclusive to -m)
  -d, --debug           Enable debugging
  -v, --verbose         'Print status messages to stdout


COPYRIGHT
=========

deblaze - A remote method enumeration tool for flex servers
Created by Jon Rose
Copyright (C) 2009-2010 Trustwave Holdings, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
 
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


