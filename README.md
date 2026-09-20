# Port_Mapper
Map the ports and processes between servers as an interactive SVG diagram and CSV spreadsheet

![Demo SVG diagram](./demo/output.svg?raw=true)
##### Note: this image is likely not interactive here due to browser security policies

---

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

Run `port_mapper.py -e` to allow ephemeral ports to connect to other ephemeral ports

Run `port_mapper.py -r` to NOT replace ephemeral ports in the csv
 - This will probably make your csv massive

Run `port_mapper.py -k` to keep unique ephemeral ports in the diagram instead of merging them by process

Run `port_mapper.py -v` to generate a static svg instead of an interactive one

Run `port_mapper.py -g` to prevent different arguments to the same process being grouped under one process
 - Useful if the diagram becomes unreadable when a few processes run dozens of times with different arguments

Run `port_mapper.py -d <path/to/known_hosts_file>` to choose the known hosts file
 - This file will act as the DNS resolver for unknown hosts
 - Useful if your system is connecting to servers not included in the input files, but you know the IPs and hostnames

Run `port_mapper.py -x <exclude_file>` to choose the exclude file, that is, which processes are ignored
 - `-!x` inverts this argument

Run `port_mapper.py -c` to include closed connections
 - `-!c` includes ONLY closed connections

Run `port_mapper.py -p` to only include processes with associated ports
 - `-!p` inverts this argument

Run `port_mapper.py -u <user1> <user2...>` to only include processes being run by the given user(s)
 - Only works if your input files list associated user(s)
 - `-!u` inverts this argument

Run `port_mapper.py -s <state1> <state2...>` to only include the given state(s)
 - `-!s` inverts this argument

Run `port_mapper.py -l <proto1> <proto2...>` to only include the given protocol(s)
 - `-!l` inverts this argument

---

## Linux:
### Get the ports:
 - `sudo netstat -pan > ${HOSTNAME}_netstat.txt`
   - **OR**
 - `sudo netstat -panc > ${HOSTNAME}_netstat.txt`
   - Updates every second, needs to be stopped with `CTRL + C`
### Get the processes:
 - `sudo ps -ef > ${HOSTNAME}_ps.txt`
   - **OR**
 - `while sleep 1; do sudo ps -ef >> ${HOSTNAME}_ps.txt; done`
   - Updates every second, needs to be stopped with `CTRL + C`

---

## Windows (cmd, preferred):
### Get the ports:
 - `netstat -anoq > %COMPUTERNAME%_netstat.txt`
    - **OR**
 - `netstat -anoq 1 > %COMPUTERNAME%_netstat.txt`
   - Updates every second, needs to be stopped with `CTRL + C`
### Get the processes:
 - `ps -ef > %COMPUTERNAME%_ps.txt`
   - To be clear, this `ps` is a port of Linux's `ps`, NOT an alias of powershell's `Get-Process`
   - **OR**
 - `for /l %l in (0,0,1) do @(ps -ef >> %COMPUTERNAME%_ps.txt && timeout /t 1)`
   - Updates every second, needs to be stopped with `CTRL + C`

---

## Windows (powershell):
### Get the ports:
 - `netstat -anoq > ${Env:COMPUTERNAME}_netstat.txt`
    - **OR**
 - `netstat -anoq 1 > %COMPUTERNAME%_netstat.txt`
   - Updates every second, needs to be stopped with `CTRL + C`
### Get the processes:
 - `Get-CimInstance Win32_Process | select ProcessId, Name, CommandLine > ${Env:COMPUTERNAME}_ps.txt`
  - **OR**
 - `while(1){Get-CimInstance Win32_Process | select ProcessId, Name, CommandLine >> ${Env:COMPUTERNAME}_ps.txt;sleep 1}`
    - Updates every second, needs to be stopped with `CTRL + C`
   - **OR**
 - `Get-WmiObject Win32_Process | select ProcessId, Name, CommandLine > ${Env:COMPUTERNAME}_ps.txt`
  - **OR**
 - `while(1){Get-WmiObject Win32_Process | select ProcessId, Name, CommandLine >> ${Env:COMPUTERNAME}_ps.txt;sleep 1}`
    - Updates every second, needs to be stopped with `CTRL + C`
