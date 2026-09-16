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

Run `port_mapper.py -i <path/to/input_dir>` to choose the input directory(s)

Run `port_mapper.py -o <path/to/output_file>` to choose the output file

Run `port_mapper.py -j <path/to/plantuml.jar>` to specify where `plantuml.jar` is

Run `port_mapper.py -e` to NOT mark ephemeral ports in the csv
 - This will probably make your csv massive

Run `port_mapper.py -x <exlude_file>` to choose the exclude file, that is, which processes are ignored
 - `-!x` inverts this argument

Run `port_mapper.py -c` to include closed connections
 - `-!c` includes ONLY closed connections

Run `port_mapper.py -p` to only include processes with associated ports
 - `-!p` inverts this argument

Run `port_mapper.py -u <user1> <user2...>` to only include processes being run by the given user(s)
 - `-!u` inverts this argument

Run `port_mapper.py -s <state1> <state2...>` to only include the given state(s)
 - `-!s` inverts this argument

Run `port_mapper.py -l <proto1> <proto2...>` to only include the given protocol(s)
 - `-!l` inverts this argument

## Linux:
 - `sudo netstat -pan > ${HOSTNAME}_netstat.txt`
 - `sudo ps -ef > ${HOSTNAME}_ps.txt`

## Windows (cmd, preferred):
 - `netstat -anoq > %COMPUTERNAME%_netstat.txt`
 - `ps -ef > %COMPUTERNAME%_ps.txt`
   - To be clear, this `ps` is a port of Linux's `ps`, NOT an alias of powershell's `Get-Process`

## Windows (powershell):
 - `netstat -anoq > ${Env:COMPUTERNAME}_netstat.txt`
 - `Get-CimInstance Win32_Process | select ProcessId, Name, CommandLine > ${Env:COMPUTERNAME}_ps.txt`
   - **OR**
 - `Get-WmiObject Win32_Process | select ProcessId, Name, CommandLine > ${Env:COMPUTERNAME}_ps.txt`

## ToDo:
 - Make the svg interactive such that clicking nodes and connections highlights the connections
