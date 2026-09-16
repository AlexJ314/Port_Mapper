""" port_mapper.py - Map the ports and processes between servers """
# Linux:
#   sudo netstat -pan > ${HOSTNAME}_netstat.txt
#   sudo ps -ef > ${HOSTNAME}_ps.txt
#
# Windows (powershell):
#   netstat -anoq > ${Env:COMPUTERNAME}_netstat.txt
#   Get-WmiObject Win32_Process | select ProcessId, Name, CommandLine > ${Env:COMPUTERNAME}_ps.txt
#     OR
#   Get-CimInstance Win32_Process | select ProcessId, Name, CommandLine > ${Env:COMPUTERNAME}_ps.txt
#
# Windows (cmd):
#   netstat -anoq > %COMPUTERNAME%_netstat.txt
#   ps -ef > %COMPUTERNAME%_ps.txt


import io, os, re, argparse, shlex, subprocess, csv



GLOBALS = {
    "IN_DIR" : ["./input"],
    "OUT_FILE" : "./output.puml",
    "EXCLUDE_FILE" : "./exclude.cfg",
    "INV_EXCLUDE_FILE" : None,
    "EPHEMERAL" : 32768,
    "INCLUDE_CLOSED" : False,
    "PORTS_ONLY" : False,
    "USERS" : None,
    "INV_USERS" : None,
    "PLANT_UML" : "plantuml.jar",
}
MATCHER = {}
DNS = {}
SERVER = {}
SERVER_MAP = {}
EXCLUDED = []
CONNECTIONS = {}


def main(args):
    ''' Set up and run the thing '''
    setup(args)
    read_exclude()
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
    GLOBALS.update({"INCLUDE_CLOSED" : args.c})
    GLOBALS.update({"PORTS_ONLY" : args.p})
    GLOBALS.update({"USERS" : args.u})
    GLOBALS.update({"INV_USERS" : args.__dict__.get("!u")})
    GLOBALS.update({"PLANT_UML" : args.j})

    MATCHER.update({
        "HOST" : re.compile(r"([a-z0-9\-]+)", re.IGNORECASE),
        "LOCAL_IP" : re.compile(r"(\[*(?:(?:0+\.*\:*)+|"
                               r"(?:f+\.*\:*)+|"
                               r"(?:\:+0?1?)+|"
                               r"(?:\.+0?1?)+|"
                               r"(?:127\.0\.0\.1)"
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
                "HEADER" : re.compile(r"ProcessId\s+Name\s+CommandLine", re.IGNORECASE),
                "PARSER" : parse_windows_gp,
                "FULL_MATCH" : re.compile(r"([\-\d]+)\s+"                  # PID
                                           r"((?:.(?!\s{2,}))*[^\s])\s*"    # Process
                                           r"(.*)"                          # CMD
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
    for line in fin:
        line = line.strip()
        if len(line) < 3:
            continue
        if ftype is None:
            ftype = guess_type(line)
        elif MATCHER.get("TYPE").get(ftype).get("PARSER")(host, line) is None:
            print(f"Stopped reading at `{line}`")
            break
    return ftype


def guess_type(line):
    ''' Figure out what command was used to generate this input file '''

    for (m, r) in MATCHER.get("TYPE").items():
        if r.get("HEADER").match(line):
            print(f"{m}")
            return m
    return None


def add_dns(hostname, ip):
    ''' Adds a record to the DNS '''

    if MATCHER.get("LOCAL_IP").fullmatch(ip):
        return

    record = DNS.setdefault(ip, [])
    if hostname not in record:
        record.append(hostname)


def get_dns(ip, local_host, local_port, remote_port, state, proto):
    ''' Gets DNS record '''

    if ip is None:
        return [None]

    if MATCHER.get("LOCAL_IP").fullmatch(ip):
        return [local_host]

    if DNS.get(ip) is None and ip not in ('*',):
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


def parse_linux_ps(host, line):
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

    if "-" in pid:
        # Skip; it's part of the header
        return matched

    if (inv_e := GLOBALS.get("INV_EXCLUDE_FILE")) is None and args[0] in EXCLUDED:
        return matched
    if inv_e is not None and args[0] not in EXCLUDED:
        return matched

    if (users := GLOBALS.get("USERS")) is not None and uid not in users:
        return matched
    if (users := GLOBALS.get("INV_USERS")) is not None and uid in users:
        return matched

    SERVER.get(host).get("PS").update({
        f"{pid}" : {
            "UID" : uid,
            "PID" : pid,
            "PPID" : ppid,
            "C" : c,
            "STIME" : stime,
            "TTY" : tty,
            "TIME" : time,
            "PROCESS" : args[0],
            "ARGS" : shlex.join(args[1:])
        }
    })
    return matched


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

    add_dns(host, local_host)

    if "*" in local_port:
        # Don't bother if the port isn't set up
        print(f"WARNING: Local port isn't set up: `{line}`")
        return matched

    port_type = "port"
    if state in ("listening", "listen", "syn_received", "syn_recv") or remote_port in ("*", "0", ""):
        port_type = "portin"
    elif state in ("syn_send", "syn_sent"):
        port_type = "portout"
    if not GLOBALS.get("INCLUDE_CLOSED") and state in ("close_wait","closed","close","fin_wait_1","fin_wait1","fin_wait_2","fin_wait2","last_ack","timed_wait","time_wait","closing","bound"):
        return matched

    if (inv_e := GLOBALS.get("INV_EXCLUDE_FILE")) is None and process in EXCLUDED:
        return matched
    if inv_e is not None and process not in EXCLUDED:
        return matched

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
        "PORT_TYPE" : port_type,
    }

    pp = SERVER.get(host).get("NETSTAT").setdefault(f"{local_port}_{proto}", [])
    pp.append(new_val)

    return matched


def parse_windows_gp(host, line):
    ''' Match a Windows Get-CimInstance OR Get-WmiObject output '''

    matched = MATCHER.get("TYPE").get("WINDOWS_GP").get("FULL_MATCH").match(line)
    if matched is None:
        return None

    pid = matched.group(1).lower()
    process = matched.group(2).lower()
    args = matched.group(3).lower()

    if "-" in pid:
        # Skip; it's part of the header
        return matched

    if (inv_e := GLOBALS.get("INV_EXCLUDE_FILE")) is None and process in EXCLUDED:
        return matched
    if inv_e is not None and process not in EXCLUDED:
        return matched

    SERVER.get(host).get("PS").update({
        f"{pid}" : {
            "PID" : pid,
            "PROCESS" : process,
            "ARGS" : args,
        }
    })
    return matched


def parse_windows_ps(host, line):
    ''' Match a Windows ps output '''

    matched = MATCHER.get("TYPE").get("WINDOWS_PS").get("FULL_MATCH").match(line)
    if matched is None:
        return None

    uid = matched.group(1).lower()
    pid = matched.group(2).lower()
    ppid = matched.group(3).lower()
    stime = matched.group(4).lower()
    args = shlex.split(matched.group(5).lower(), posix=False)

    if (inv_e := GLOBALS.get("INV_EXCLUDE_FILE")) is None and args[0] in EXCLUDED:
        return matched
    if inv_e is not None and args[0] not in EXCLUDED:
        return matched

    if (users := GLOBALS.get("USERS")) is not None and uid not in users:
        return matched
    if (users := GLOBALS.get("INV_USERS")) is not None and uid in users:
        return matched

    SERVER.get(host).get("PS").update({
        f"{pid}" : {
            "UID" : uid,
            "PID" : pid,
            "PPID" : ppid,
            "STIME" : stime,
            "PROCESS" : args[0],
            "ARGS" : shlex.join(args[1:])
        }
    })
    return matched


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

    add_dns(host, local_host)

    if "*" in local_port:
        # Don't bother if the port isn't set up
        print(f"WARNING: Local port isn't set up: `{line}`")
        return matched

    port_type = "port"
    if state in ("listening", "listen", "syn_received", "syn_recv") or remote_port in ("*", "0", ""):
        port_type = "portin"
    elif state in ("syn_send", "syn_sent"):
        port_type = "portout"
    if not GLOBALS.get("INCLUDE_CLOSED") and state in ("close_wait","closed","close","fin_wait_1","fin_wait1","fin_wait_2","fin_wait2","last_ack","timed_wait","time_wait","closing","bound"):
        return matched

    if MATCHER.get("IPV6").fullmatch(local_host) or MATCHER.get("IPV6").fullmatch(remote_host):
        proto += "6"

    new_val = {
        "PROTO" : proto,
        "LOCAL_HOST" : local_host,
        "LOCAL_PORT" : local_port,
        "REMOTE_HOST" : remote_host,
        "REMOTE_PORT" : remote_port,
        "STATE" : state,
        "PID" : pid,
        "PORT_TYPE" : port_type,
    }

    pp = SERVER.get(host).get("NETSTAT").setdefault(f"{local_port}_{proto}", [])
    pp.append(new_val)

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
        EXCLUDED.append(line.strip())


def map_servers():
    ''' Map how servers communicate '''

    # All netstat entries update their processes with connection info
    for (hostname, server) in SERVER.items():
        for (pp, details) in server.get("NETSTAT").items():
            for detail in details:
                pid = detail.setdefault("PID", -1)
                proc = server.get("PS").setdefault(pid, {"PID" : pid, "PROCESS" : "Unknown", "ARGS" : ""})
                # Figure out the process details on the remote host
                remote_hosts = get_dns(detail.get("REMOTE_HOST"), hostname, detail.get("LOCAL_PORT"), detail.get("REMOTE_PORT"), detail.get("STATE"), detail.get("PROTO"))
                remote_process_many = []
                remote_args_many = []
                #for remote_host in remote_hosts:
                #    remote_pids = []
                #    for remote_connection in SERVER.get(remote_host, {}).get("NETSTAT", {}).get(f"{detail.get("REMOTE_PORT")}_{detail.get("PROTO")}", []):
                #        remote_pids.append(remote_connection.get("PID"))
                #    remote_process = []
                #    remote_args = []
                #    for remote_pid in remote_pids:
                #        remote_detail = SERVER.get(remote_host, {}).get("PS", {}).get(remote_pid, {})
                #        remote_process.append(remote_detail.get("PROCESS"))
                #        remote_args.append(remote_detail.get("ARGS"))
                #    remote_process_many.append(remote_process)
                #    remote_args_many.append(remote_args)
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
                })

    if GLOBALS.get("PORTS_ONLY"):
        for hostname in list(SERVER.keys()):
            for pid in list((ps := SERVER.get(hostname).get("PS")).keys()):
                if len(ps.get(pid).get("CONNECTIONS", [])) < 1:
                    del ps[pid]

    # Map by server > process > args > connections
    #   Instead of server > pid > connections
    for (hostname, server) in SERVER.items():
        s_host = SERVER_MAP.setdefault(hostname, {})
        for (pid, detail) in server.get("PS").items():
            proc = detail.get("PROCESS")
            args = detail.get("ARGS")
            s_proc = s_host.setdefault(proc, {})
            s_args = s_proc.setdefault(args, [])
            s_args += detail.setdefault("CONNECTIONS", [])


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
        define_content.append(end_node(hostname, server))

    for (hostname, server) in DNS.get("UNKNOWN", {}).items():
        define_content.append(make_node(hostname, server, label_to_port, add_label=True))
        define_content.append(end_node(hostname, server))

    return define_content + label_to_port + get_connections_puml()


def get_connections_puml():
    ''' Returns a puml list of connections '''

    return CONNECTIONS.get("PUML", [])


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

    return f"p_{puml_name_safe(hostname)}_{puml_name_safe(port)}_{puml_name_safe(proto)}"


def label_name(hostname, port, proto):
    ''' Return puml label name '''

    return f"l_{puml_name_safe(hostname)}_{puml_name_safe(port)}_{puml_name_safe(proto)}"


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
                if conn.get("PROTO").endswith("6"):
                    name = f"<u>{name}</u>"
                if int(port) >= GLOBALS.get("EPHEMERAL"):
                    name = f"<i>{name}</i>"
                else:
                    name = f"<b>{name}</b>"

                label_puml = f"  label \"{name}\" as {label_name(hostname, port, conn.get("PROTO"))}"
                port_puml = f"  {conn.get("PORT_TYPE")} \" \" as {port_name(hostname, port, conn.get("PROTO"))}"

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


def make_process(hostname, name, args):
    ''' How to start a process '''

    return f"  component \"{puml_safe(name)}\" as {process_name(hostname, name, args)} {{"


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
        ret += f"      {puml_safe(name)}\n"
    ret += "    ]"

    return ret


def end_args(hostname, name, args):
    ''' How to end args '''

    return ""


def connection_type(conn, priority=2, hidden=False):
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

    if conn.get("PORT_TYPE") == "portin":
        arrow_start = "<"
        style.append("#green")
    elif conn.get("PORT_TYPE") == "portout":
        arrow_start = ">"

    if state in ("bound",):
        style.append("#red")

    style = ",".join(style)
    if len(style) > 0:
        style = f"[{style}]"

    return f" {arrow_start}{line_start}{style}{line_end}{arrow_end} "


def make_connection(hostname, proc, args, conn):
    ''' How to make a connection '''

    connections = []

    local_port = conn.get("LOCAL_PORT")

    connections.append((f"{arg_name(hostname, proc, args)}"
                        f"{connection_type(conn, priority=2)}"
                        f"{label_name(hostname, local_port, conn.get("PROTO"))}"))

    for remote_host in conn.get("REMOTE_HOST"):
        if (remote_port := conn.get("REMOTE_PORT")) not in ("*", "0", ""):
            puml = (f"{port_name(hostname, local_port, conn.get("PROTO"))}"
                    f"{connection_type(conn, priority=-1)}"
                    f"{port_name(remote_host, remote_port, conn.get("PROTO"))}")

            rpuml = (f"{port_name(remote_host, remote_port, conn.get("PROTO"))}"
                    f"{connection_type(conn, priority=-1)}"
                    f"{port_name(hostname, local_port, conn.get("PROTO"))}")

            if puml not in CONNECTIONS.get("PUML", []) and rpuml not in CONNECTIONS.get("PUML", []):
                connections.append(puml)

    CONNECTIONS.setdefault("PUML", []).extend(connections)


def get_puml_prefix():
    ''' Boilerplate to start puml '''

    ret = ("@startuml\n"
    "!theme sunlust\n"
    "skinparam linetype ortho\n"
    "skinparam roundCorner 7\n"
    "!pragma layout elk\n"
    "'!pragma svginteractive true\n"
    "'skinparam pathHoverColor #yellow\n"
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

    csv_dump = []

    header = ["Protocol", "State", "Source Host", "Source Port", "Source Process", "Source Args",
        "Destination Host", "Destination Port", "Destination Process", "Destination Args"]
    csv_dump.append(header)

    print("Dumping to csv")
    for (hostname, server) in SERVER_MAP.items():
        for (proc, args) in server.items():
            no_connections = True
            for (arg, connections) in args.items():
                for conn in connections:
                    for (remote_host, (remote_process, remote_args)) in zip(conn.get("REMOTE_HOST"), zip(conn.get("REMOTE_PROCESS"), conn.get("REMOTE_ARGS"))):
                        for (p, a) in zip(remote_process, remote_args):
                            no_connections = False
                            row = [conn.get("PROTO"), conn.get("STATE"), hostname, conn.get("LOCAL_PORT"), proc, arg,
                                remote_host, conn.get("REMOTE_PORT"), p, a]
                            csv_dump.append(row)
            if no_connections:
                row = ["", "", hostname, "", proc, arg, "", "", "", ""]
                csv_dump.append(row)

    split_fname = GLOBALS.get("OUT_FILE").split(".")
    if len(split_fname) > 1:
        split_fname = split_fname[:-1]
    csv_file = f"{".".join(split_fname)}.csv"
    with open(csv_file, "w", encoding="utf-8", newline='') as fout:
        csv_writer = csv.writer(fout, quoting=csv.QUOTE_ALL)
        csv_writer.writerows(csv_dump)


def build_puml():
    ''' Runs plantuml.jar '''

    plantuml = GLOBALS.get("PLANT_UML")
    if os.path.isfile(plantuml):
        print("Generating diagram with PlantUML")
        subprocess.run(["java", "-jar", plantuml, GLOBALS.get("OUT_FILE"), "-tsvg"])
    else:
        print(f"Failed to find '{plantuml}' Not generating diagram")


if __name__ == "__main__":
    # Run it
    parser = argparse.ArgumentParser("port_mapper.py")
    user_parser = parser.add_mutually_exclusive_group()
    exclude_parser = parser.add_mutually_exclusive_group()
    parser.add_argument("-i", help=f"Input directory(s). Default is '{" '".join(GLOBALS.get("IN_DIR"))}'", default=GLOBALS.get("IN_DIR"), nargs="+")
    parser.add_argument("-o", help=f"Output file. Default is '{GLOBALS.get("OUT_FILE")}'", default=GLOBALS.get("OUT_FILE"))
    parser.add_argument("-j", help=f"Path to 'plantuml.jar'. Default is '{GLOBALS.get("PLANT_UML")}'", default=GLOBALS.get("PLANT_UML"))
    parser.add_argument("-c", help=f"Include closed connections. Default is False", action="store_true", default=False)
    exclude_parser.add_argument("-x", help=f"Processes to exclude. Default is '{GLOBALS.get("EXCLUDE_FILE")}'", default=GLOBALS.get("EXCLUDE_FILE"))
    exclude_parser.add_argument("-!x", help=f"Processes to NOT exclude")
    parser.add_argument("-p", help=f"Only include processes with ports", action="store_true", default=False)
    user_parser.add_argument("-u", help=f"Only include processes being run by the given user(s)", nargs="+")
    user_parser.add_argument("-!u", help=f"Only include processes NOT being run by the given user(s)", nargs="+")
    pargs = parser.parse_args()

    main(pargs)
