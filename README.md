# Port_Mapper
Map the ports and processes between servers

## How To:
On each server you're interested in, get the current lists of ports and processes as an admin user.
Save these outputs to `./input` and run `port_mapper.py`.
It will automatically generate the syntax for a [PlantUML](https://github.com/plantuml/plantuml) Deployment diagram.
If `plantuml.jar` is available in the current directory, an svg diagram will be automatically generated.

Hostnames are determined by the first valid set of characters in each filename,
so filenames of ports and processes from the same server should have the same prefix.
It doesn't matter what the rest of the filename is, so long as there's an illegal character
after the hostname (assuming you don't want the entire filename as the entire hostname).

Run `port_mapper.py -i <input_dir>` to choose the input directory

Run `port_mapper.py -o <output_file>` to choose the output file

Run `port_mapper.py -x <exlude_file>` to choose the exclude file, that is, which processes are ignored

Run `port_mapper.py -c` to include closed connections

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

## ToDo:
 - Parse Windows ps outputs
 - Dump to .csv
 - Make the svg interactive such that clicking nodes and connections highlights the connections
