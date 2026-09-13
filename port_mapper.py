""" port_mapper.py - Map the ports and processes between servers """
# Linux:
#   sudo netstat -pan > ${HOSTNAME}_netstat.txt
#   sudo ps -ef > ${HOSTNAME}_ps.txt
#
# Windows (powershell):
#   netstat -anoq > ${Env:COMPUTERNAME}_netstat.txt
#   Get-WmiObject Win32_Process > ${Env:COMPUTERNAME}_ps.txt
#
# Windows (cmd):
#   netstat -anoq > %COMPUTERNAME%_netstat.txt
#   ps -ef > %COMPUTERNAME%_ps.txt


import io, os, re, json



IN_DIR = "./input"
MATCHER = {}
SERVER = {}
SERVER_MAP = {}


def main():
    ''' Set up and run the thing '''
    setup()
    read_files()
    #print(json.dumps(SERVER, indent=2))
    # map_servers()


def setup():
    ''' Set globals '''

    MATCHER.update({
        "HOST" : re.compile(r"([a-z0-9\-]+)", re.IGNORECASE),
        "TYPE" : {
            "LINUX_PS" : {
                "HEADER" : re.compile(r"UID\s+PID\s+PPID\s+C\s+STIME\s+TTY\s+TIME\s+CMD", re.IGNORECASE),
                "PARSER" : parse_linux_ps,
            },
            "LINUX_NETSTAT" : {
                "HEADER" : re.compile(r"Proto\s+Recv-Q\s+Send-Q\s+Local Address\s+Foreign Address\s+State\s+PID/Program name\s+Timer", re.IGNORECASE),
                "PARSER" : parse_linux_netstat,
                "FULL_MATCH" : re.compile(r"([a-z\d]+)\s+"                         # Proto
                                           r"([\d]+)\s+"                            # Recv-Q
                                           r"([\d]+)\s+"                            # Send-Q
                                           r"([a-f\d\.\[\]\:\*\%]+)\:([\d\*]+)\s+"  # Local host:Port
                                           r"([a-f\d\.\[\]\:\*\%]+)\:([\d\*]+)\s+"  # Remote host:Port
                                           r"([a-z\d_]*)\s+"                        # State
                                           r"([\d]*)\/?-?([^\s{2,}]*)\s+"           # PID/Process
                                           r"(.*)"                                  # Timer
                                          , re.IGNORECASE)
            },
            "WINDOWS_GW" : {
                "HEADER" : re.compile(r"__GENUS\s+\:.*", re.IGNORECASE),
                "PARSER" : parse_windows_gw,
            },
            "WINDOWS_PS" : {
                "HEADER" : re.compile(r"TODO"),
                "PARSER" : parse_windows_ps,
            },
            "WINDOWS_NETSTAT" : {
                "HEADER" : re.compile(r"Proto\s+Local\s+Address\s+Foreign\s+Address\s+State\s+PID", re.IGNORECASE),
                "PARSER" : parse_windows_netstat,
                "FULL_MATCH" : re.compile(r"([a-z\d]+)\s+"                         # Proto
                                           r"([a-f\d\.\[\]\:\*\%]+)\:([\d\*]+)\s+"  # Local host:Port
                                           r"([a-f\d\.\[\]\:\*\%]+)\:([\d\*]+)\s+"  # Remote host:Port
                                           r"([a-z\d_]*)\s+"                        # State
                                           r"([\d]+)"                               # PID
                                          , re.IGNORECASE)
            },
        },
    })


def read_files():
    ''' Read the files in the input directory '''

    for fname in os.listdir(IN_DIR):
        if not os.path.isfile(os.path.join(IN_DIR, fname)):
            print(f"{fname} is not a file. Skipping")
            continue

        if (host := MATCHER.get("HOST").match(fname)) is None:
            print(f"{fname} does not start with a valid hostname. Skipping")
            continue

        host = host.group(1)
        if SERVER.get(host) is None:
            SERVER.update({host : {"PS" : {}, "NETSTAT" : {}}})

        print(f"\nReading {fname}")
        try:
            with open(os.path.join(IN_DIR, fname), "r", encoding="utf-16") as fin:
                parse_file(fin, host)
        except UnicodeError:
            with open(os.path.join(IN_DIR, fname), "r", encoding="utf-8") as fin:
                parse_file(fin, host)


def parse_file(fin, host):
    ''' Try to parse each line of an input file '''

    ftype = None
    for line in fin:
        line = line.strip()
        if len(line) < 3:
            continue
        if ftype is None:
            ftype = guess_type(line)
        elif MATCHER.get("TYPE").get(ftype).get("PARSER")(host, line) is None:
            break


def guess_type(line):
    ''' Figure out what command was used to generate this input file '''

    for (m, r) in MATCHER.get("TYPE").items():
        if r.get("HEADER").match(line):
            print(f"{m}")
            return m
    return None


def parse_linux_ps(host, line):
    ''' Match a Linux ps output '''

    print("TODO Linux ps")
    return None


def parse_linux_netstat(host, line):
    ''' Match a Linux netstat output '''

    matched = MATCHER.get("TYPE").get("LINUX_NETSTAT").get("FULL_MATCH").match(line)
    if matched is None:
        return None

    proto = matched.group(1).lower()
    recv_q = matched.group(2).lower()
    send_q = matched.group(3).lower()
    local_host = matched.group(4).lower()
    local_port = matched.group(5).lower()
    remote_host = matched.group(6).lower()
    remote_port = matched.group(7).lower()
    state = matched.group(8).lower()
    pid = matched.group(9).lower()
    process = matched.group(10).lower()
    timer = matched.group(11).lower()

    if "*" in local_port:
        # Don't bother if the port isn't set up
        print(f"WARNING: Local port isn't set up: `{line}`")
        return matched

    SERVER.get(host).get("NETSTAT").update({
        f"{local_port}_{proto}" : {
            "PROTO" : proto,
            "RECV_Q" : recv_q,
            "SEND_Q" : send_q,
            "LOCAL_HOST" : local_host,
            "LOCAL_PORT" : local_port,
            "REMOTE_HOST" : remote_host,
            "REMOTE_PORT" : remote_port,
            "STATE" : state,
            "PID" : pid,
            "PROCESS" : process,
            "timer" : timer,
        }
    })
    return matched


def parse_windows_gw(host, line):
    ''' Match a Windows Get-WmiObject output '''

    print("TODO Windows gw")
    return None


def parse_windows_ps(host, line):
    ''' Match a Windows ps output '''

    print("TODO Windows ps")
    return None


def parse_windows_netstat(host, line):
    ''' Match a Windows netstat output '''

    matched = MATCHER.get("TYPE").get("WINDOWS_NETSTAT").get("FULL_MATCH").match(line)
    if matched is None:
        return None

    proto = matched.group(1).lower()
    local_host = matched.group(2).lower()
    local_port = matched.group(3).lower()
    remote_host = matched.group(4).lower()
    remote_port = matched.group(5).lower()
    state = matched.group(6).lower()
    pid = matched.group(7).lower()

    if "*" in local_port:
        # Don't bother if the port isn't set up
        print(f"WARNING: Local port isn't set up: `{line}`")
        return matched

    SERVER.get(host).get("NETSTAT").update({
        f"{local_port}_{proto}" : {
            "PROTO" : proto,
            "LOCAL_HOST" : local_host,
            "LOCAL_PORT" : local_port,
            "REMOTE_HOST" : remote_host,
            "REMOTE_PORT" : remote_port,
            "STATE" : state,
            "PID" : pid,
        }
    })
    return matched


if __name__ == "__main__":
    # Run it
    main()
