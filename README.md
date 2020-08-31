# FortiSIEM Integration with Oracle CASB Cloud Service

## What is it?:

This repo provides a package allowing FortiSIEM users to ingest Oracle CASB events and parse them. it is an API Client python implementation of oracle CASB focused on fetching Risk Events and User Risk Scores and a connector which converts CASB events into syslogs which are then sent to SIEM/ Syslog Server.

A FortiSIEM parser is provied to parse these events.

## Deployment:

- Download the content of OracleCASB_API_Client directory and copy it to FortiSIEM collector (or any other machine with a python interpreter)
- chmod +x occs.py (-h for detailed arguments)
	- exp: ./occs.py -s siem.collector.acme.com -k XXXXXXX -a YYYYYY -b https://api-loric-eu.palerra.net -t6
- schedule occs.py in chron to run each X number of hours
- Import the parser in OCCS_FortiSIEM_Parser directory into FortiSIEM
- Change/create the associated event attributes as required, the provided parser uses only built-in ones

## License:
Apache License, Version 2.0