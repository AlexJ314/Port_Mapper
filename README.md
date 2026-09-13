# Port_Mapper
Map the ports and processes between servers

## How To:
On each server you're interested in, get the current lists of ports and processes as an admin user.
Save these outputs to `./input` and run `port_mapper.py`.
It will automatically generate a PlantUML Deployment diagram.

Hostnames are determined by the first valid set of characters in each filename,
so filenames of ports and processes from the same server should have the same prefix.
It doesn't matter what the rest of the filename is, so long as there's an illegal character
after the hostname (assuming you don't want the entire filename as the entire hostname).

Run `port_mapper.py -i <input_dir>` to choose the input directory

## Linux:
 - `sudo netstat -pan > ${HOSTNAME}_netstat.txt`
 - `sudo ps -ef > ${HOSTNAME}_ps.txt`

## Windows (powershell, preferred):
 - `netstat -anoq > ${Env:COMPUTERNAME}_netstat.txt`
 - `Get-WmiObject Win32_Process | select ProcessId, Name, CommandLine > ${Env:COMPUTERNAME}_ps.txt`
   - **OR**
 - `Get-CimInstance Win32_Process | select ProcessId, Name, CommandLine > ${Env:COMPUTERNAME}_ps.txt`

## Windows (cmd):
 - `netstat -anoq > %COMPUTERNAME%_netstat.txt`
 - `ps -ef > %COMPUTERNAME%_ps.txt`
   - To be clear, this `ps` is a port of Linux's `ps`, NOT an alias of powershell's `Get-Process`
