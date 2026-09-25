""" port_mapper.py - Map the ports and processes between servers """
# Linux:
#   Get ports:
#     sudo netstat -pan > ${HOSTNAME}_netstat.txt
#       OR
#     sudo netstat -panc > ${HOSTNAME}_netstat.txt
#
#   Get processes:
#     sudo ps -ef > ${HOSTNAME}_ps.txt
#       OR
#     while sleep 1; do sudo ps -ef >> ${HOSTNAME}_ps.txt; done
#
#
# Windows (cmd):
#   Get ports:
#     netstat -anoq > %COMPUTERNAME%_netstat.txt
#       OR
#     netstat -anoq 1 > %COMPUTERNAME%_netstat.txt
#
#   Get processes:
#     ps -ef > %COMPUTERNAME%_ps.txt
#       OR
#     for /l %l in (0,0,1) do @(ps -ef >> %COMPUTERNAME%_ps.txt && timeout /t 1)
#
#
# Windows (powershell):
#   Get ports:
#     netstat -anoq > ${Env:COMPUTERNAME}_netstat.txt
#       OR
#     netstat -anoq 1 > ${Env:COMPUTERNAME}_netstat.txt
#
#   Get processes:
#     Get-WmiObject Win32_Process | select ProcessId, Name, CommandLine > ${Env:COMPUTERNAME}_ps.txt
#       OR
#     while(1){Get-CimInstance Win32_Process | select ProcessId, Name, CommandLine >> ${Env:COMPUTERNAME}_ps.txt;sleep 1}
#       OR
#     Get-CimInstance Win32_Process | select ProcessId, Name, CommandLine > ${Env:COMPUTERNAME}_ps.txt
#       OR
#     while(1){Get-WmiObject Win32_Process | select ProcessId, Name, CommandLine >> ${Env:COMPUTERNAME}_ps.txt;sleep 1}


import io, os, re, argparse, shlex, subprocess, csv
import xml.etree.ElementTree as ET



GLOBALS = {
    "IN_DIR" : ["./input"],
    "OUT_FILE" : "./output.puml",
    "EXCLUDE_FILE" : "./exclude.cfg",
    "INV_EXCLUDE_FILE" : None,
    "KNOWN_FILE" : "./known_hosts.cfg",
    "EPHEMERAL" : 32768,
    "INCLUDE_CLOSED" : False,
    "INV_INCLUDE_CLOSED" : False,
    "PORTS_ONLY" : False,
    "INV_PORTS_ONLY" : False,
    "USERS" : None,
    "INV_USERS" : None,
    "PLANT_UML" : "plantuml.jar",
    "STATES" : None,
    "INV_STATES" : None,
    "PROTOS" : None,
    "INV_PROTOS" : None,
    "REPLACE_EPHEMERAL" : True,
    "NO_EPHEMERAL" : True,
    "GROUP" : False,
    "PRUNE_EPHEMERAL" : True,
    "NO_INTERACTIVE" : False,
    "SVG_FUNCTION" : "./svg_function.svg",
}
MATCHER = {}
DNS = {}
SERVER = {}
SERVER_MAP = {}
EXCLUDED = {}
CONNECTIONS = {}
RENAMED = {}


def main(args):
    ''' Set up and run the thing '''
    setup(args)
    read_exclude()
    read_known()
    read_dirs()
    map_servers()
    write_puml()
    build_puml()
    dump_csv()
    print("Done")


def setup(args):
    ''' Set globals '''

    GLOBALS.update({"IN_DIR" : args.i})
    GLOBALS.update({"OUT_FILE" : args.o})
    GLOBALS.update({"EXCLUDE_FILE" : args.x})
    GLOBALS.update({"INV_EXCLUDE_FILE" : args.__dict__.get("!x")})
    GLOBALS.update({"KNOWN_FILE" : args.d})
    GLOBALS.update({"INCLUDE_CLOSED" : args.c})
    GLOBALS.update({"INV_INCLUDE_CLOSED" : args.__dict__.get("!c")})
    GLOBALS.update({"PORTS_ONLY" : args.p})
    GLOBALS.update({"INV_PORTS_ONLY" : args.__dict__.get("!p")})
    GLOBALS.update({"USERS" : args.u})
    GLOBALS.update({"INV_USERS" : args.__dict__.get("!u")})
    GLOBALS.update({"PLANT_UML" : args.j})
    GLOBALS.update({"STATES" : args.s})
    GLOBALS.update({"INV_STATES" : args.__dict__.get("!s")})
    GLOBALS.update({"PROTOS" : args.l})
    GLOBALS.update({"INV_PROTOS" : args.__dict__.get("!l")})
    GLOBALS.update({"REPLACE_EPHEMERAL" : args.r})
    GLOBALS.update({"NO_EPHEMERAL" : args.e})
    GLOBALS.update({"PRUNE_EPHEMERAL" : args.k})
    GLOBALS.update({"NO_INTERACTIVE" : args.v})
    GLOBALS.update({"GROUP" : args.g})

    MATCHER.update({
        "HOST" : re.compile(r"([a-z0-9\-]+)", re.IGNORECASE),
        "LOCAL_IP" : re.compile(r"(\[*(?:(?:0+\.*\:*)+|"
                               r"(?:f+\.*\:*)+|"
                               r"(?:[\:\.0]+)1?|"
                               r"(?:127\.\d+\.\d+\.\d+)"
                               r")\]*)", re.IGNORECASE),
        "IPV6" : re.compile(r"([^\.*]+)", re.IGNORECASE),
        "TYPE" : {
            "LINUX_PS" : {
                "HEADER" : re.compile(r"UID\s+PID\s+PPID\s+C\s+STIME\s+TTY\s+TIME\s+CMD", re.IGNORECASE),
                "PARSER" : parse_linux_ps,
                "FULL_MATCH" : re.compile(r"((?:.(?!\s{2,}))*[^\s])\s+"        # UID
                                           r"([\d]+)\s+"                        # PID
                                           r"([-\d]+)\s+"                       # PPID
                                           r"([\d]+)\s+"                        # C
                                           r"([^\s]*)\s+"                       # STIME
                                           r"([^\s]+)\s+"                       # TTY
                                           r"([^\s]+)\s+"                       # TIME
                                           r"[\-\/]*((?:.(?!\s{2,}))*[^\s])\s*" # CMD
                                          , re.IGNORECASE),
            },
            "LINUX_NETSTAT" : {
                "HEADER" : re.compile(r"Proto\s+Recv-Q\s+Send-Q\s+Local Address\s+Foreign Address\s+State\s+PID/Program name\s*(?:Timer)?", re.IGNORECASE),
                "PARSER" : parse_linux_netstat,
                "FULL_MATCH" : re.compile(r"([a-z\d]+)\s+"                              # Proto
                                           r"([\d]+)\s+"                                # Recv-Q
                                           r"([\d]+)\s+"                                # Send-Q
                                           r"([a-f\d\.\[\]\:\*\%]+)\:([\d\*]+)\s+"      # Local host:Port
                                           r"([a-f\d\.\[\]\:\*\%]+)\:([\d\*]+)\s+"      # Remote host:Port
                                           r"([a-z\d_]*)\s+"                            # State
                                           r"([\d]*)\/?-?((?:.(?!\s{2,}))*[^\s])\s*"    # PID/Process
                                           r"(.*)"                                      # Timer
                                          , re.IGNORECASE),
            },
            "WINDOWS_GP" : {
                "HEADER" : re.compile(r"ProcessId\s+(Name\s+)CommandLine", re.IGNORECASE),
                "PARSER" : parse_windows_gp,
                "FULL_MATCH" : re.compile(r"([\-\d]+)\s+"                  # PID
                                           r"(.*)\s*"                      # Process and CMD
                                          , re.IGNORECASE),
            },
            "WINDOWS_PS" : {
                "HEADER" : re.compile(r"UID\s+PID\s+PPID\s+STIME\s+CMD", re.IGNORECASE),
                "PARSER" : parse_windows_ps,
                "FULL_MATCH" : re.compile(r"((?:.(?!\s{2,}))*[^\s])\s+"         # UID
                                           r"([\d]+)\s+"                        # PID
                                           r"([-\d]+)\s+"                       # PPID
                                           r"([^\s]*)\s+"                       # STIME
                                           r"[\-\/]*((?:.(?!\s{2,}))*[^\s])\s*" # CMD
                                          , re.IGNORECASE),
            },
            "WINDOWS_NETSTAT" : {
                "HEADER" : re.compile(r"Proto\s+Local\s+Address\s+Foreign\s+Address\s+State\s+PID", re.IGNORECASE),
                "PARSER" : parse_windows_netstat,
                "FULL_MATCH" : re.compile(r"([a-z\d]+)\s+"                         # Proto
                                           r"([a-f\d\.\[\]\:\*\%]+)\:([\d\*]+)\s+"  # Local host:Port
                                           r"([a-f\d\.\[\]\:\*\%]+)\:([\d\*]+)\s+"  # Remote host:Port
                                           r"([a-z\d_]*)\s+"                        # State
                                           r"([\d]+)"                               # PID
                                          , re.IGNORECASE),
            },
        },
    })


def read_dirs():
    ''' Reads each input directory '''

    for in_dir in GLOBALS.get("IN_DIR"):
        if not os.path.isdir(in_dir):
            print(f"{in_dir} is not an input directory. Skipping")
        else:
            read_files(in_dir)


def read_files(in_dir):
    ''' Read the files in the input directory '''

    print(f"Reading {in_dir}")

    for fname in os.listdir(in_dir):
        if not os.path.isfile(os.path.join(in_dir, fname)):
            print(f"{fname} is not an input file. Skipping")
            continue

        if (host := MATCHER.get("HOST").match(fname)) is None:
            print(f"{fname} does not start with a valid hostname. Skipping")
            continue

        host = host.group(1)
        SERVER.setdefault(host, {"PS" : {}, "NETSTAT" : {}})

        print(f"Reading {fname}")
        try:
            with open(os.path.join(in_dir, fname), "r", encoding="utf-8") as fin:
                if parse_file(fin, host) is None:
                    print(f"Failed to determine type of `{fname}`")
        except UnicodeError:
            with open(os.path.join(in_dir, fname), "r", encoding="utf-16") as fin:
                if parse_file(fin, host) is None:
                    print(f"Failed to determine type of `{fname}`")

        if len(SERVER.get(host).get("PS")) < 1 and len(SERVER.get(host).get("NETSTAT")) < 1:
            del SERVER[host]


def parse_file(fin, host):
    ''' Try to parse each line of an input file '''

    ftype = None
    last_ftype = None
    for line in fin:
        line = line.strip()
        if len(line) < 3:
            continue
        if ftype is None:
            (ftype, match_group) = guess_type(line)
        elif MATCHER.get("TYPE").get(ftype).get("PARSER")(host, line, match_group) is None:
            last_ftype = ftype
            ftype = None
    return ftype if last_ftype is None else last_ftype


def guess_type(line):
    ''' Figure out what command was used to generate this input file '''

    for (m, r) in MATCHER.get("TYPE").items():
        if g := r.get("HEADER").match(line):
            print(f"{m}")
            return (m, g)
    return (None, None)


def closed_states():
    ''' What to consider closed states '''

    return ("close_wait","closed","close","fin_wait_1","fin_wait1","fin_wait_2","fin_wait2","last_ack","timed_wait","time_wait","closing",)


def shared_ps(value, host):
    ''' Process parsing shared between types '''

    inv_e = GLOBALS.get("INV_EXCLUDE_FILE")
    users = GLOBALS.get("USERS")
    inv_users = GLOBALS.get("INV_USERS")

    pid = value.get("PID", "")
    if (process := value.get("PROCESS")) is None:
        value.update({"PROCESS" : f"PID: {pid if pid != "" else "-1"}"})
        process = value.get("PROCESS")
    if value.get("ARGS") is None:
        value.update({"ARGS" : ""})
    uid = value.get("UID", "")

    if "-" in pid:
        # Skip; it's part of the header
        return False

    if inv_e is None and process in EXCLUDED.setdefault("PROCESSES", []):
        EXCLUDED.setdefault("HOSTNAME", {}).setdefault(host, []).append(pid)
        return False
    if inv_e is not None and process not in EXCLUDED.setdefault("PROCESSES", []):
        EXCLUDED.setdefault("HOSTNAME", {}).setdefault(host, []).append(pid)
        return False

    if users is not None and uid not in users:
        return False
    if inv_users is not None and uid in inv_users:
        return False

    if not GLOBALS.get("GROUP"):
        value.update({"PROCESS" : f"{process}?{pid}"})

    SERVER.get(host).get("PS").update({
        f"{pid}" : value,
    })

    return True


def shared_netstat(value, host):
    ''' Netstat parsing shared between types '''

    port_type = "port"

    inv_e = GLOBALS.get("INV_EXCLUDE_FILE")
    states = GLOBALS.get("STATES")
    inv_states = GLOBALS.get("INV_STATES")
    protos = GLOBALS.get("PROTOS")
    inv_protos = GLOBALS.get("INV_PROTOS")

    local_host = value.get("LOCAL_HOST", "")
    local_port = value.get("LOCAL_PORT", "")
    state = value.get("STATE", "")
    remote_port = value.get("REMOTE_PORT", "")
    remote_host = value.get("REMOTE_HOST", "")
    process = value.get("PROCESS", "")
    pid = value.get("PID", "")
    state = value.get("STATE", "")
    proto = value.get("PROTO", "")

    add_dns(host, local_host)

    if "*" in local_port:
        # Don't bother if the port isn't set up
        return False

    if state in ("listening", "listen", "syn_received", "syn_recv") or remote_port in ("*", "0", "") or not is_ephemeral(local_port):
        port_type += "_portin"
    if state in ("syn_send", "syn_sent") or is_ephemeral(local_port):
        port_type += "_portout"
    value.update({"PORT_TYPE" : port_type})

    if local_port in ("*", ""):
        local_port = "0"
        value.update({"LOCAL_PORT" : local_port})
    if remote_port in ("*", ""):
        remote_port = "0"
        value.update({"REMOTE_PORT" : remote_port})

    if remote_host == "*":
        remote_host = ""
        value.update({"REMOTE_HOST" : remote_host})

    if not GLOBALS.get("INV_INCLUDE_CLOSED"):
        if not GLOBALS.get("INCLUDE_CLOSED") and state in closed_states():
            return False
    elif state not in closed_states():
        return False

    if inv_e is None and process in EXCLUDED.setdefault("PROCESSES", []):
        EXCLUDED.setdefault("HOSTNAME", {}).setdefault(host, []).append(pid)
        return False
    if inv_e is not None and process not in EXCLUDED.setdefault("PROCESSES", []):
        EXCLUDED.setdefault("HOSTNAME", {}).setdefault(host, []).append(pid)
        return False

    if states is not None and state not in states:
        return False
    if inv_states is not None and state in inv_states:
        return False

    if protos is not None and proto not in protos:
        return False
    if inv_protos is not None and proto in inv_protos:
        return False

    pp = SERVER.get(host).get("NETSTAT").setdefault(f"{local_port}_{proto}", [])
    try:
        pp.remove(value)
    except ValueError:
        pass
    finally:
        pp.append(value)

    return True


def parse_linux_ps(host, line, header_match):
    ''' Match a Linux ps output '''

    matched = MATCHER.get("TYPE").get("LINUX_PS").get("FULL_MATCH").match(line)
    if matched is None:
        return None

    uid = matched.group(1).lower()
    pid = matched.group(2).lower()
    ppid = matched.group(3).lower()
    c = matched.group(4).lower()
    stime = matched.group(5).lower()
    tty = matched.group(6).lower()
    time = matched.group(7).lower()
    args = shlex.split(matched.group(8).lower(), posix=False)
    process = args[0]
    args = shlex.join(args[1:])

    new_val = {
        "UID" : uid,
        "PID" : pid,
        "PPID" : ppid,
        "C" : c,
        "STIME" : stime,
        "TTY" : tty,
        "TIME" : time,
        "PROCESS" : process,
        "ARGS" : args,
    }

    shared_ps(new_val, host)

    return matched


def parse_linux_netstat(host, line, header_match):
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

    new_val = {
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
        "TIMER" : timer,
    }

    shared_netstat(new_val, host)

    return matched


def parse_windows_gp(host, line, header_match):
    ''' Match a Windows Get-CimInstance OR Get-WmiObject output '''

    matched = MATCHER.get("TYPE").get("WINDOWS_GP").get("FULL_MATCH").match(line)
    if matched is None:
        return None

    pid = matched.group(1).lower()
    args = matched.group(2).lower()
    process = args[0:len(header_match.group(1))].strip()
    args = args[len(header_match.group(1)):]

    new_val = {
        "PID" : pid,
        "PROCESS" : process,
        "ARGS" : args,
    }

    shared_ps(new_val, host)

    return matched


def parse_windows_ps(host, line, header_match):
    ''' Match a Windows ps output '''

    matched = MATCHER.get("TYPE").get("WINDOWS_PS").get("FULL_MATCH").match(line)
    if matched is None:
        return None

    uid = matched.group(1).lower()
    pid = matched.group(2).lower()
    ppid = matched.group(3).lower()
    stime = matched.group(4).lower()
    args = shlex.split(matched.group(5).lower(), posix=False)
    process = args[0]
    args = shlex.join(args[1:])

    new_val = {
        "UID" : uid,
        "PID" : pid,
        "PPID" : ppid,
        "STIME" : stime,
        "PROCESS" : process,
        "ARGS" : args,
    }

    shared_ps(new_val, host)

    return matched


def parse_windows_netstat(host, line, header_match):
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

    new_val = {
        "PROTO" : proto,
        "LOCAL_HOST" : local_host,
        "LOCAL_PORT" : local_port,
        "REMOTE_HOST" : remote_host,
        "REMOTE_PORT" : remote_port,
        "STATE" : state,
        "PID" : pid,
    }

    shared_netstat(new_val, host)

    return matched


def read_exclude():
    ''' Reads excluded processes '''

    exclude_file = GLOBALS.get("INV_EXCLUDE_FILE")
    if exclude_file is None:
        exclude_file = GLOBALS.get("EXCLUDE_FILE")
    if not os.path.isfile(exclude_file):
        print(f"Failed to find exclude file `{exclude_file}`")
        return

    print("Reading exclude file")
    try:
        with open(exclude_file, "r", encoding="utf-8") as fin:
            parse_exclude_file(fin)
    except UnicodeError:
        with open(exclude_file, "r", encoding="utf-16") as fin:
            parse_exclude_file(fin)


def parse_exclude_file(fin):
    ''' Parses the given exclude file '''

    for line in fin:
        line = line.strip()
        if line.startswith("#"):
            continue
        EXCLUDED.setdefault("PROCESSES", []).append(line)


def read_known():
    ''' Reads configured known hosts '''

    DNS.setdefault("KNOWN_HOSTS", {})
    known_file = GLOBALS.get("KNOWN_FILE")
    if not os.path.isfile(known_file):
        print(f"Failed to find known hosts file `{known_file}`")
        return

    print("Reading known hosts file")
    try:
        with open(known_file, "r", encoding="utf-8") as fin:
            parse_known_file(fin)
    except UnicodeError:
        with open(known_file, "r", encoding="utf-16") as fin:
            parse_known_file(fin)


def parse_known_file(fin):
    ''' Parses the given known hosts file '''

    for line in fin:
        line = line.strip().split()
        ip = line[0]
        host = " ".join(line[1:])
        if len(ip) < 1 or len(host) < 1 or ip.startswith("#"):
            continue
        DNS.setdefault("KNOWN_HOSTS", {}).update({ip : host})


def is_ephemeral(port):
    ''' How to determine if a port is ephemeral '''

    if port in ("*", "0"):
        return False

    if port.startswith("ephemeral"):
        return True

    return safe_int(port) >= GLOBALS.get("EPHEMERAL")


def map_servers():
    ''' Map how servers communicate '''

    print("Mapping servers")

    # All netstat entries update their processes with connection info
    for (hostname, server) in SERVER.items():
        print(hostname)
        for (pp, details) in server.get("NETSTAT").items():
            for detail in details:
                pid = detail.setdefault("PID", "-1")
                if pid in EXCLUDED.get("HOSTNAME", {}).get(hostname, []):
                    continue
                l_lp = detail.get("LOCAL_PORT")
                l_rp = detail.get("REMOTE_PORT")
                if GLOBALS.get("NO_EPHEMERAL") and is_ephemeral(l_lp) and is_ephemeral(l_rp):
                    continue
                proc = server.get("PS").setdefault(pid, {"PID" : pid, "PROCESS" : f"PID: {pid if pid != "" else "-1"}", "ARGS" : "Unknown"})
                # Figure out the process details on the remote host
                remote_hosts = get_dns(detail.get("REMOTE_HOST"), hostname, l_lp, l_rp, detail.get("STATE"), detail.get("PROTO"))
                remote_process_many = []
                remote_args_many = []
                for remote_host in remote_hosts:
                    remote_pids = []
                    for rc in SERVER.get(remote_host, {}).get("NETSTAT", {}).get(f"{l_rp}_{detail.get("PROTO")}", []):
                        r_pid = rc.get("PID")
                        if r_pid in EXCLUDED.get("HOSTNAME", {}).get(remote_host, []):
                            continue
                        r_lp = rc.get("LOCAL_PORT")
                        r_rp = rc.get("REMOTE_PORT")
                        if hostname not in get_dns(rc.get("REMOTE_HOST"), remote_host, r_lp, r_rp, rc.get("STATE"), rc.get("PROTO")):
                            continue
                        if not ((l_lp == r_rp and l_rp == r_lp)):
                            if not (l_rp == "0" or r_rp == "0"):
                                continue
                        remote_pids.append(r_pid)
                    remote_process = []
                    remote_args = []
                    for remote_pid in remote_pids:
                        remote_detail = SERVER.get(remote_host, {}).get("PS", {}).get(remote_pid, {})
                        remote_process.append(remote_detail.get("PROCESS"))
                        remote_args.append(remote_detail.get("ARGS"))
                    remote_process_many.append(remote_process)
                    remote_args_many.append(remote_args)
                # Add the connection
                conn = proc.setdefault("CONNECTIONS", [])
                conn.append({
                    "LOCAL_HOST" : get_dns(detail.get("LOCAL_HOST"), hostname, detail.get("LOCAL_PORT"), detail.get("LOCAL_PORT"), detail.get("STATE"), detail.get("PROTO")),
                    "LOCAL_PORT" : detail.get("LOCAL_PORT"),
                    "PORT_TYPE" : detail.get("PORT_TYPE"),
                    "PROTO" : detail.get("PROTO"),
                    "REMOTE_HOST" : remote_hosts,
                    "REMOTE_PORT" : detail.get("REMOTE_PORT"),
                    "STATE" : detail.get("STATE"),
                    "REMOTE_PROCESS" : remote_process_many,
                    "REMOTE_ARGS" : remote_args_many,
                    "LOCAL_PROCESS" : proc.get("PROCESS"),
                    "LOCAL_ARGS" : proc.get("ARGS"),
                })

    if GLOBALS.get("PORTS_ONLY") or GLOBALS.get("INV_PORTS_ONLY"):
        for hostname in list(SERVER.keys()):
            for pid in list((ps := SERVER.get(hostname).get("PS")).keys()):
                if GLOBALS.get("PORTS_ONLY") and len(ps.get(pid).get("CONNECTIONS", [])) < 1 :
                    del ps[pid]
                if GLOBALS.get("INV_PORTS_ONLY") and len(ps.get(pid).get("CONNECTIONS", [])) >= 1 :
                    del ps[pid]

    # Map by server > process > args > connections
    #   Instead of server > pid > connections
    for (hostname, server) in SERVER.items():
        s_host = SERVER_MAP.setdefault(hostname, {})
        print(hostname)
        for (pid, detail) in server.get("PS").items():
            proc = detail.get("PROCESS")
            args = detail.get("ARGS")
            s_proc = s_host.setdefault(proc, {})
            s_args = s_proc.setdefault(args, [])
            for c in detail.setdefault("CONNECTIONS", []):
                if GLOBALS.get("PRUNE_EPHEMERAL") and (not c.get("STATE") == "bound") and is_ephemeral(c.get("LOCAL_PORT")):
                    name = f"ephemeral_{hostname}_{puml_name_safe(proc)}_{puml_name_safe(c.get("PROTO"))}_{puml_name_safe(args)}"
                    org = port_name(hostname, c.get("LOCAL_PORT"), c.get("PROTO"))
                    RENAMED.update({org : name})
                if c not in s_args:
                    s_args.append(c)


def add_dns(hostname, ip):
    ''' Adds a record to the DNS '''

    if ip is None or ip == "":
        return

    if MATCHER.get("LOCAL_IP").fullmatch(ip):
        return

    record = DNS.setdefault(ip, [])
    if hostname not in record:
        record.append(hostname)


def get_dns(ip, local_host, local_port, remote_port, state, proto):
    ''' Gets DNS record '''

    if ip is None or ip == "":
        return [None]

    if MATCHER.get("LOCAL_IP").fullmatch(ip):
        return [local_host]

    if DNS.get(ip) is None and not ip == "":
        if (nickname := DNS.get("KNOWN_HOSTS", {}).get(ip)) is not None:
            ip = nickname
        unknown = DNS.setdefault("UNKNOWN", {})
        server = unknown.setdefault(ip, {})
        proc = server.setdefault(f"{remote_port}_{proto}", {})
        args = proc.setdefault(f"{remote_port}_{proto}", [])
        args.append({"LOCAL_HOST" : ip,
                     "LOCAL_PORT" : remote_port,
                     "PORT_TYPE" : "port",
                     "PROTO" : proto,
                     "STATE" : state,
                     "REMOTE_HOST" : local_host,
                     "REMOTE_PORT" : local_port,
        })

    return DNS.get(ip, [ip])


def write_puml():
    ''' Write PlantUML to file '''

    print("Writing puml")
    content = convert_to_puml()
    prefix = get_puml_prefix()
    suffix = get_puml_suffix()

    with open(GLOBALS.get("OUT_FILE"), "w", encoding="utf-8") as fout:
        fout.write(prefix)
        fout.write("\n".join(content))
        fout.write(suffix)


def convert_to_puml():
    ''' Convert server map to PlantUML '''

    define_content = []
    label_to_port = []
    for (hostname, server) in SERVER_MAP.items():
        define_content.append(make_node(hostname, server, label_to_port))
        for (proc, args) in server.items():
            define_content.append(make_process(hostname, proc, args))
            for (arg, connections) in args.items():
                define_content.append(make_args(hostname, proc, arg))
                for conn in connections:
                    make_connection(hostname, proc, arg, conn)
                define_content.append(end_args(hostname, proc, arg))
            define_content.append(end_process(hostname, proc, args))
        if not remove_empty_node(define_content):
            define_content.append(end_node(hostname, server))

    for (hostname, server) in DNS.get("UNKNOWN", {}).items():
        define_content.append(make_node(hostname, server, label_to_port, add_label=True))
        define_content.append(end_node(hostname, server))

    return define_content + label_to_port + list(get_connections_puml())


def get_connections_puml():
    ''' Returns a puml list of connections '''

    return CONNECTIONS.setdefault("PUML", set())


def puml_name_safe(string):
    ''' Make names safe for puml '''

    if not isinstance(string, str):
        string = f"{string}"

    return puml_safe(string, False)


def puml_safe(string, unicode=True):
    ''' Make strings safe for puml '''

    if not isinstance(string, str):
        string = f"{string}"

    ret = ""
    allowed_chars = (list(range(ord('0'), ord('9')+1)) +
                     list(range(ord('A'), ord('Z')+1)) +
                     list(range(ord('a'), ord('z')+1)))
    for c in string:
        if ord(c) not in allowed_chars:
            if unicode:
                c = f"<U+{ord(c):04X}>"
            else:
                c = f"U{ord(c):04X}"
        ret += c

    return ret


def node_name(hostname):
    ''' Return puml node name '''

    return f"n_{puml_name_safe(hostname)}"


def process_name(hostname, name, args):
    ''' Return puml process name '''

    return f"c_{puml_name_safe(hostname)}_{puml_name_safe(name)}"


def arg_name(hostname, name, args):
    ''' Return puml arg name '''

    return f"cd_{puml_name_safe(hostname)}_{puml_name_safe(name)}_{puml_name_safe(args)}"


def port_name(hostname, port, proto):
    ''' Return puml port name '''

    name = f"p_{puml_name_safe(hostname)}_{puml_name_safe(port)}_{puml_name_safe(proto)}"

    return RENAMED.get(name, name)


def label_name(hostname, port, proto):
    ''' Return puml label name '''

    return f"l_{port_name(hostname, port, proto)}"


def make_node(hostname, server, _conns, add_label=False):
    ''' How to start a node '''

    ret = []

    if add_label:
        ret.append(f"node \" \" as {node_name(hostname)} {{")
        ret.append(f"  label \"<b>{puml_safe(hostname)}</b>\" as l{node_name(hostname)}")
        ret.append(f"  {node_name(hostname)} -[hidden]u- l{node_name(hostname)}")
    else:
        ret.append(f"node \"{puml_safe(hostname)}\" as {node_name(hostname)} {{")

    for (proc, args) in server.items():
        for (arg, connections) in args.items():
            for conn in connections:
                name = (port := conn.get("LOCAL_PORT"))
                if is_ephemeral(port):
                    if GLOBALS.get("PRUNE_EPHEMERAL"):
                        name = "ephemeral"
                    name = f"<i>{name}</i>"
                else:
                    name = f"<b>{name}</b>"
                if conn.get("PROTO").endswith("6"):
                    name = f"<u>{name}</u>"

                label_puml = f"  label \"{name}\" as {label_name(hostname, port, conn.get("PROTO"))}"
                port_puml = f"  port \" \" as {port_name(hostname, port, conn.get("PROTO"))}"

                if label_puml not in ret and port_puml not in ret:
                    ret.append(label_puml)
                    ret.append(port_puml)

                label_to_port = (f"{label_name(hostname, port, conn.get("PROTO"))}"
                                 f"{connection_type(conn, priority=2)}"
                                 f"{port_name(hostname, port, conn.get("PROTO"))}")
                if label_to_port not in _conns:
                    _conns.append(label_to_port)

    return "\n".join(ret)


def end_node(hostname, server):
    ''' How to end a node '''

    return "}"


def remove_empty_node(content):
    ''' Removes an empty node from the content list '''

    if content[-1].strip().startswith("node \""):
        content.pop(-1)
        return True

    return False


def make_process(hostname, name, args):
    ''' How to start a process '''

    display_name = name
    if not GLOBALS.get("GROUP"):
        display_name = name.split("?")[0]

    return f"  component \"{puml_safe(display_name)}\" as {process_name(hostname, name, args)} {{"


def end_process(hostname, name, args):
    ''' How to end a process '''

    return "  }"


def make_args(hostname, name, args):
    ''' How to start args '''

    ret = f"    card {arg_name(hostname, name, args)}"
    args = puml_safe(args)
    ret += " [\n"
    if len(args) > 1:
        ret += f"      {args}\n"
    else:
        if not GLOBALS.get("GROUP"):
            name = name.split("?")[0]
        ret += f"      {puml_safe(name)}\n"
    ret += "    ]"

    return ret


def end_args(hostname, name, args):
    ''' How to end args '''

    return ""


def connection_type(conn, priority=2, hidden=False, port_to_port=False):
    ''' What the arrows look like '''

    line_start = "-"
    line_end = "-"
    arrow_start = ""
    arrow_end = ""
    style = []

    if hidden:
        style.append("hidden")

    if priority > 2:
        line_start = '-' * (priority - 1)
    elif priority < 1:
        style.append("norank")

    if (state := conn.get("STATE")) in ("close_wait","closed","close","fin_wait_1","fin_wait1","fin_wait_2","fin_wait2","last_ack","timed_wait","time_wait","closing",):
        style.append("dotted,norank")
    elif conn.get("PROTO") not in ("tcp","tcp6",):
        style.append("dashed")

    for c in conn.get("REMOTE_HOST", []):
        if c not in conn.get("LOCAL_HOST") and "#blue" not in style:
            style.append("#blue")

    if not port_to_port:
        if "portin" in conn.get("PORT_TYPE"):
            arrow_start = "<"
        if "portout" in conn.get("PORT_TYPE"):
            arrow_end = ">"

    if state in ("bound",):
        style.append("#red")
    elif state in ("listen", "listening"):
        style.append("#green")

    style = ",".join(style)
    if len(style) > 0:
        style = f"[{style}]"

    return f" {arrow_start}{line_start}{style}{line_end}{arrow_end} "


def safe_int(val):
    ''' Make ports safe for ints '''

    if val == "*":
        return 0

    if val.startswith("ephemeral"):
        return 2**16

    return int(val)


def orient_connection(conn):
    ''' Orient the connection such that the ephemeral port is remote '''

    lp = conn.get("LOCAL_PORT")
    rp = conn.get("REMOTE_PORT")

    remote = "REMOTE"
    local = "LOCAL"
    if safe_int(lp) > safe_int(rp) and safe_int(rp) > 0:
        remote = "LOCAL"
        local = "REMOTE"

    new_conn = {}
    for (key, val) in conn.items():
        if "REMOTE" in key:
            new_conn.update({key.replace("REMOTE", remote) : val})
        elif "LOCAL" in key:
            if ("PROCESS" in key or "ARGS" in key) and not isinstance(val, list):
                val = [[val]*len(conn.get("LOCAL_HOST"))]
            new_conn.update({key.replace("LOCAL", local) : val})
        else:
            new_conn.update({key : val})
    conn = new_conn

    lp = conn.get("LOCAL_PORT")
    rp = conn.get("REMOTE_PORT")

    if GLOBALS.get("REPLACE_EPHEMERAL"):
        if is_ephemeral(lp):
            lp = "ephemeral"
        if is_ephemeral(rp):
            rp = "ephemeral"

    new_conns = set()
    sout = io.StringIO()
    csv_writer = csv.writer(sout, quoting=csv.QUOTE_MINIMAL)
    for lh in conn.get("LOCAL_HOST"):
        for rh in conn.get("REMOTE_HOST"):
            for (rprocs, rargs) in zip(conn.get("REMOTE_PROCESS"), conn.get("REMOTE_ARGS")):
                for (procs, args) in zip(conn.get("LOCAL_PROCESS"), conn.get("LOCAL_ARGS")):
                    if len(procs) == 0:
                            procs = [""]
                            args = [""]
                    for (proc, arg) in zip(procs, args):
                        proc = proc.split("?")[0]
                        if len(rprocs) == 0:
                            rprocs = [""]
                            rargs = [""]
                        for (rproc, rarg) in zip(rprocs, rargs):
                            rproc = rproc.split("?")[0]
                            row = [conn.get("PROTO"), conn.get("STATE"), lh, proc, arg, lp, rh, rproc, rarg, rp,]
                            csv_writer.writerow(row)

    for line in sout.getvalue().splitlines():
        new_conns.add(line + "\n")

    return new_conns


def make_connection(hostname, proc, args, conn):
    ''' How to make a connection '''

    connections = CONNECTIONS.setdefault("PUML", set())
    details = CONNECTIONS.setdefault("DETAILS", set())

    local_port = conn.get("LOCAL_PORT")

    puml = (f"{arg_name(hostname, proc, args)}"
            f"{connection_type(conn, priority=2)}"
            f"{label_name(hostname, local_port, conn.get("PROTO"))}")

    if puml not in connections:
        connections.add(puml)

    for remote_host in conn.get("REMOTE_HOST"):
        if not (remote_port := conn.get("REMOTE_PORT")) == "0":
            puml = (f"{port_name(hostname, local_port, conn.get("PROTO"))}"
                    f"{connection_type(conn, priority=-1, port_to_port=True)}"
                    f"{port_name(remote_host, remote_port, conn.get("PROTO"))}")

            rpuml = (f"{port_name(remote_host, remote_port, conn.get("PROTO"))}"
                    f"{connection_type(conn, priority=-1, port_to_port=True)}"
                    f"{port_name(hostname, local_port, conn.get("PROTO"))}")

            if rpuml not in connections:
                connections.add(puml)

        details.update(orient_connection(conn))


def get_puml_prefix():
    ''' Boilerplate to start puml '''

    ret = ("@startuml\n"
    "scale 0.5\n"
    "!theme sunlust\n"
    "skinparam linetype ortho\n"
    "skinparam roundCorner 7\n"
    "!pragma layout elk\n"
    "<style>\n"
    "    process {\n"
    "        LineColor \"#FFF\"\n"
    "        BackGroundColor \"#FFF\"\n"
    "    }\n"
    "    node {\n"
    "        LineColor $colors.green\n"
    "        BackgroundColor $colors.green_bg\n"
    "    }\n"
    "</style>\n"
    "legend top left\n"
    "   <color:$colors.font>Loopback Port</color>\n"
    "   <color:#blue>External Port</color>\n"
    "   <color:#green>Listening Port</color>\n"
    "   <color:#red>Bound Socket</color>\n"
    "   <b>Registered Port</b>\n"
    "   <i>Ephemeral Port</i>\n"
    "   <u>IPv6 Port</u>\n"
    "   Solid: Open, TCP\n"
    "   Dashed: Open, non-TCP\n"
    "   Dotted: Closed\n"
    "end legend\n")

    return ret

def get_puml_suffix():
    ''' Boilerplate to end puml '''

    ret = ("\n@enduml\n")

    return ret


def dump_csv():
    ''' Dump connections to csv '''

    print("Dumping to csv")

    header = ["Protocol", "State", "Source Host", "Source Process", "Source Args", "Source Port",
        "Destination Host", "Destination Process", "Destination Args", "Destination Port"]

    split_fname = GLOBALS.get("OUT_FILE").split(".")
    if len(split_fname) > 1:
        split_fname = split_fname[:-1]
    csv_file = f"{".".join(split_fname)}.csv"

    sout = io.StringIO()
    csv_writer = csv.writer(sout, quoting=csv.QUOTE_MINIMAL)
    csv_writer.writerow(header)

    with open(csv_file, "w", encoding="utf-8", newline='') as fout:
        fout.write(sout.getvalue())
        fout.writelines(sorted(list(CONNECTIONS.setdefault("DETAILS", set()))))
        csv_writer = csv.writer(fout, quoting=csv.QUOTE_MINIMAL)
        for (hostname, server) in SERVER_MAP.items():
            for (proc, args) in server.items():
                proc = proc.split("?")[0]
                for (arg, connections) in args.items():
                    if len(connections) == 0:
                        csv_writer.writerow(["", "", hostname, proc, arg, "", "", "", "", ""])


def build_puml():
    ''' Runs plantuml.jar '''

    plantuml = GLOBALS.get("PLANT_UML")
    if os.path.isfile(plantuml):
        print("Generating diagram with PlantUML")
        subprocess.run(["java", "-jar", plantuml, GLOBALS.get("OUT_FILE"), "-tsvg"])
        split_fname = GLOBALS.get("OUT_FILE").split(".")
        if len(split_fname) > 1:
            split_fname = split_fname[:-1]
        svg_file = f"{".".join(split_fname)}.svg"
        make_interactive(svg_file)
    else:
        print(f"Failed to find '{plantuml}' Not generating diagram")


def make_interactive(svg_file):
    ''' Adds functions to make the svg interactive '''

    if GLOBALS.get("NO_INTERACTIVE"):
        return

    if not os.path.isfile(GLOBALS.get("SVG_FUNCTION")):
        print(f"Failed to find SVG function file `{GLOBALS.get("SVG_FUNCTION")}`. SVG will not be interactive")
        return

    if not os.path.isfile(svg_file):
        print(f"Failed to find `{svg_file}` to add interactive functionality to")
        return

    print("Making SVG interactive")

    # Load the svgs
    svg_function = ET.parse(GLOBALS.get("SVG_FUNCTION")).getroot()
    svg_puml = ET.parse(svg_file)

    # Add the functions
    svg_puml.getroot().append(svg_function)

    # Write the svg
    ET.register_namespace("", "http://www.w3.org/2000/svg")
    svg_puml.write(svg_file)


def build_arg_parse():
    ''' Build Arg Parse '''

    parser = argparse.ArgumentParser("port_mapper.py")
    exclude_parser = parser.add_mutually_exclusive_group()
    port_parser = parser.add_mutually_exclusive_group()
    user_parser = parser.add_mutually_exclusive_group()
    state_parser = parser.add_mutually_exclusive_group()
    proto_parser = parser.add_mutually_exclusive_group()

    parser.add_argument("-i", help=f"Input directory(s). Default is '{" '".join(GLOBALS.get("IN_DIR"))}'", default=GLOBALS.get("IN_DIR"), nargs="+")
    parser.add_argument("-o", help=f"Output file. Default is '{GLOBALS.get("OUT_FILE")}'", default=GLOBALS.get("OUT_FILE"))
    parser.add_argument("-j", help=f"Path to 'plantuml.jar'. Default is '{GLOBALS.get("PLANT_UML")}'", default=GLOBALS.get("PLANT_UML"))
    parser.add_argument("-e", help=f"Allow ephemeral ports to connect to other ephemeral ports. Default is '{not GLOBALS.get("NO_EPHEMERAL")}'", action=f"store_{not GLOBALS.get("NO_EPHEMERAL")}".lower(), default=GLOBALS.get("NO_EPHEMERAL"))
    parser.add_argument("-r", help=f"Do NOT replace ephemeral ports in csv with 'ephemeral'. Default is '{not GLOBALS.get("REPLACE_EPHEMERAL")}'", action=f"store_{not GLOBALS.get("REPLACE_EPHEMERAL")}".lower(), default=GLOBALS.get("REPLACE_EPHEMERAL"))
    parser.add_argument("-k", help=f"Keep ephemeral ports in diagram instead of pruning. Default is '{not GLOBALS.get("PRUNE_EPHEMERAL")}'", action=f"store_{not GLOBALS.get("PRUNE_EPHEMERAL")}".lower(), default=GLOBALS.get("PRUNE_EPHEMERAL"))
    parser.add_argument("-v", help=f"Generate a static SVG instead of interactive. Default is '{GLOBALS.get("NO_INTERACTIVE")}'", action=f"store_{not GLOBALS.get("NO_INTERACTIVE")}".lower(), default=GLOBALS.get("NO_INTERACTIVE"))
    parser.add_argument("-g", help=f"Group many args under the same process. Default is '{GLOBALS.get("GROUP")}'", action=f"store_{not GLOBALS.get("GROUP")}".lower(), default=GLOBALS.get("GROUP"))
    parser.add_argument("-d", help=f"DNS file of known hosts. Default is '{GLOBALS.get("KNOWN_FILE")}'", default=GLOBALS.get("KNOWN_FILE"))
    exclude_parser.add_argument("-x", help=f"File of processes to exclude. Default is '{GLOBALS.get("EXCLUDE_FILE")}'", default=GLOBALS.get("EXCLUDE_FILE"))
    exclude_parser.add_argument("-!x", help=f"File of processes to NOT exclude")
    port_parser.add_argument("-p", help=f"Only include processes with ports", action="store_true", default=False)
    port_parser.add_argument("-!p", help=f"Only include processes WITHOUT ports", action="store_true", default=False)
    user_parser.add_argument("-u", help=f"Only include processes being run by the given user(s)", nargs="+")
    user_parser.add_argument("-!u", help=f"Only include processes NOT being run by the given user(s)", nargs="+")
    state_parser.add_argument("-c", help=f"Include closed connections. Default is False", action="store_true", default=False)
    state_parser.add_argument("-!c", help=f"Include ONLY closed connections. Default is False", action="store_true", default=False)
    state_parser.add_argument("-s", help=f"Only include the given state(s)", nargs="+")
    state_parser.add_argument("-!s", help=f"Only include NOT the given state(s)", nargs="+")
    proto_parser.add_argument("-l", help=f"Only include the given protocol(s)", nargs="+")
    proto_parser.add_argument("-!l", help=f"Only include NOT the given protocol(s)", nargs="+")

    return parser


if __name__ == "__main__":
    # Run it
    pargs = build_arg_parse().parse_args()

    main(pargs)
