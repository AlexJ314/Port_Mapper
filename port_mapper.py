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
    "IN_DIR" : "./input",
    "OUT_FILE" : "./output.puml",
    "EXCLUDE_FILE" : "./exclude.cfg",
    "EPHEMERAL" : 32768,
    "CLOSED" : False,
}
MATCHER = {}
DNS = {}
SERVER = {}
SERVER_MAP = {}
EXCLUDED = []


def main(args):
    ''' Set up and run the thing '''
    setup(args)
    read_exclude()
    read_files()
    map_servers()
    write_puml()
    dump_csv()
    build_puml()
    print("Done")


def setup(args):
    ''' Set globals '''

    GLOBALS.update({"IN_DIR" : args.i})
    GLOBALS.update({"OUT_FILE" : args.o})
    GLOBALS.update({"EXCLUDE_FILE" : args.x})
    GLOBALS.update({"CLOSED" : args.c})

    MATCHER.update({
        "HOST" : re.compile(r"([a-z0-9\-]+)", re.IGNORECASE),
        "BAD_IP" : re.compile(r"(\[*(?:(?:0+\.*\:*)+|"
                               r"(?:f+\.*\:*)+|"
                               r"(?:\:+0?1?)+|"
                               r"(?:\.+0?1?)+|"
                               r"(?:127\.0\.0\.1)"
                               r")\]*)", re.IGNORECASE),
        "TYPE" : {
            "LINUX_PS" : {
                "HEADER" : re.compile(r"UID\s+PID\s+PPID\s+C\s+STIME\s+TTY\s+TIME\s+CMD", re.IGNORECASE),
                "PARSER" : parse_linux_ps,
                "FULL_MATCH" : re.compile(r"((?:.(?!\s{2,}))*[^\s])\s+"        # UID
                                           r"([\d]+)\s+"                        # PID
                                           r"([\d]+)\s+"                        # PPID
                                           r"([\d]+)\s+"                        # C
                                           r"([^\s]+)\s+"                       # STIME
                                           r"([^\s]+)\s+"                       # TTY
                                           r"([^\s]+)\s+"                       # TIME
                                           r"[\-\/]*((?:.(?!\s{2,}))*[^\s])\s*" # CMD
                                          , re.IGNORECASE),
            },
            "LINUX_NETSTAT" : {
                "HEADER" : re.compile(r"Proto\s+Recv-Q\s+Send-Q\s+Local Address\s+Foreign Address\s+State\s+PID/Program name\s+Timer", re.IGNORECASE),
                "PARSER" : parse_linux_netstat,
                "FULL_MATCH" : re.compile(r"([a-z\d]+)\s+"                             # Proto
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
                                           r"([^-\d]+)\s+"                      # PPID
                                           r"([^\s]+)\s+"                       # STIME
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


def read_files():
    ''' Read the files in the input directory '''

    print("Reading input files")
    for fname in os.listdir(GLOBALS.get("IN_DIR")):
        if not os.path.isfile(os.path.join(GLOBALS.get("IN_DIR"), fname)):
            print(f"{fname} is not a file. Skipping")
            continue

        if (host := MATCHER.get("HOST").match(fname)) is None:
            print(f"{fname} does not start with a valid hostname. Skipping")
            continue

        host = host.group(1)
        SERVER.setdefault(host, {"PS" : {}, "NETSTAT" : {}})

        print(f"\nReading {fname}")
        try:
            with open(os.path.join(GLOBALS.get("IN_DIR"), fname), "r", encoding="utf-8") as fin:
                parse_file(fin, host)
        except UnicodeError:
            with open(os.path.join(GLOBALS.get("IN_DIR"), fname), "r", encoding="utf-16") as fin:
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
            print(f"Stopped reading at `{line}`")
            break


def guess_type(line):
    ''' Figure out what command was used to generate this input file '''

    for (m, r) in MATCHER.get("TYPE").items():
        if r.get("HEADER").match(line):
            print(f"{m}")
            return m
    return None


def add_dns(hostname, ip):
    ''' Adds a record to the DNS '''

    if MATCHER.get("BAD_IP").fullmatch(ip):
        return

    record = DNS.setdefault(ip, [])
    if hostname not in record:
        record.append(hostname)


def get_dns(hostname, ip, port, proto):
    ''' Gets DNS record '''

    if ip is None:
        return [None]

    if MATCHER.get("BAD_IP").fullmatch(ip):
        return [hostname]

    if DNS.get(ip) is None and ip not in ('*',):
        unknown = DNS.setdefault("UNKNOWN", {})
        server = unknown.setdefault(ip, {})
        server.update({f"{port}_{proto}" :
                            {"LOCAL_HOST" : ip,
                             "LOCAL_PORT" : port,
                             "PORT_TYPE" : "port",
                             "PROTO" : proto,
        }})

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

    if args[0] in EXCLUDED:
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
    if state in ("listening", "listen", "syn_received", "syn_recv") or remote_port in ("*", "0"):
        port_type = "portin"
    elif state in ("syn_send", "syn_sent"):
        port_type = "portout"
    if not GLOBALS.get("CLOSED") and state in ("close_wait","closed","close","fin_wait_1","fin_wait1","fin_wait_2","fin_wait2","last_ack","timed_wait","time_wait","closing","bound"):
        return matched

    if process in EXCLUDED:
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

    if process in EXCLUDED:
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
    stime = matched.group(5).lower()
    args = shlex.split(matched.group(8).lower(), posix=False)

    if args[0] in EXCLUDED:
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
    if state in ("listening", "listen", "syn_received", "syn_recv") or remote_port in ("*", "0"):
        port_type = "portin"
    elif state in ("syn_send", "syn_sent"):
        port_type = "portout"
    if not GLOBALS.get("CLOSED") and state in ("close_wait","closed","close","fin_wait_1","fin_wait1","fin_wait_2","fin_wait2","last_ack","timed_wait","time_wait","closing","bound"):
        return matched

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

    print("Reading exclude file")
    try:
        with open(GLOBALS.get("EXCLUDE_FILE"), "r", encoding="utf-8") as fin:
            parse_exclude_file(fin)
    except UnicodeError:
        with open(GLOBALS.get("EXCLUDE_FILE"), "r", encoding="utf-16") as fin:
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
                pid = detail.get("PID")
                if pid is None:
                    continue
                proc = server.get("PS").get(pid)
                if proc is None:
                    continue
                conn = proc.setdefault("CONNECTIONS", [])
                conn.append({
                    "LOCAL_HOST" : get_dns(hostname, detail.get("LOCAL_HOST"), detail.get("LOCAL_PORT"), detail.get("PROTO")),
                    "LOCAL_PORT" : detail.get("LOCAL_PORT"),
                    "PORT_TYPE" : detail.get("PORT_TYPE"),
                    "PROTO" : detail.get("PROTO"),
                    "REMOTE_HOST" : get_dns(hostname, detail.get("REMOTE_HOST"), detail.get("REMOTE_PORT"), detail.get("PROTO")),
                    "REMOTE_PORT" : detail.get("REMOTE_PORT"),
                    "STATE" : detail.get("STATE"),
                })

    # Map by server > process > args > connections
    #   Instead of server > pid > connections
    for (hostname, server) in SERVER.items():
        s_host = SERVER_MAP.setdefault(hostname, {})
        for (pid, detail) in server.get("PS").items():
            proc = detail.get("PROCESS")
            args = detail.get("ARGS")
            s_proc = s_host.setdefault(proc, {})
            s_args = s_proc.setdefault(args, [])
            s_args += detail.get("CONNECTIONS", [])


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
    connect_content = []
    for (hostname, server) in SERVER_MAP.items():
        define_content.append(make_node(hostname, server, connect_content))
        for (proc, args) in server.items():
            define_content.append(make_process(hostname, proc, args))
            for (arg, connections) in args.items():
                define_content.append(make_args(hostname, proc, arg))
                for conn in connections:
                    connect_content.append(make_connection(hostname, proc, arg, conn))
                    connect_content.append(end_connection(hostname, proc, arg, conn))
                define_content.append(end_args(hostname, proc, arg))
            define_content.append(end_process(hostname, proc, args))
        define_content.append(end_node(hostname, server))

    for (hostname, server) in DNS.get("UNKNOWN").items():
        define_content.append(make_unknown_node(hostname, server, connect_content))
        define_content.append(end_unknown_node(hostname, server))

    return define_content + connect_content


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
                c = f"_{ord(c):04X}"
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

    return f"cd_{puml_name_safe(hostname)}_{puml_name_safe(name)}_{puml_name_safe(hash(args))}"


def port_name(hostname, port, proto):
    ''' Return puml port name '''

    return f"p_{puml_name_safe(hostname)}_{puml_name_safe(port)}_{puml_name_safe(proto)}"


def label_name(hostname, port, proto):
    ''' Return puml label name '''

    return f"l_{puml_name_safe(hostname)}_{puml_name_safe(port)}_{puml_name_safe(proto)}"


def make_node(hostname, server, _conns):
    ''' How to start a node '''

    ret = f"node \"{puml_safe(hostname)}\" as {node_name(hostname)} {{\n"

    for (pp, connections) in SERVER.get(hostname).get("NETSTAT").items():
        for connection in connections:
            name = (port := connection.get("LOCAL_PORT"))
            if int(port) >= GLOBALS.get("EPHEMERAL"):
                name = f"<i>{name}</i>"
            else:
                name = f"<b>{name}</b>"
            ret += f"  label \"{name}\" as {label_name(hostname, port, connection.get("PROTO"))}\n"
            ret += f"  {connection.get("PORT_TYPE")} \" \" as {port_name(hostname, port, connection.get("PROTO"))}\n"
            _conns.append((f"{label_name(hostname, port, connection.get("PROTO"))}"
                           f"{connection_type(connection, priority=2)}"
                           f"{port_name(hostname, port, connection.get("PROTO"))}"))

    return ret


def end_node(hostname, server):
    ''' How to end a node '''

    return "}"


def make_unknown_node(hostname, server, _conns):
    ''' How to start an unknown node '''

    ret = f"node \" \" as {node_name(hostname)} {{\n"
    ret += f"  label \"<b>{puml_safe(hostname)}</b>\" as l{node_name(hostname)}\n"
    ret += f"  {node_name(hostname)} -[hidden]u- l{node_name(hostname)}\n"

    for (pp, connections) in server.items():
        name = (port := connections.get("LOCAL_PORT"))
        if int(port) >= GLOBALS.get("EPHEMERAL"):
            name = f"<i>{name}</i>"
        else:
            name = f"<b>{name}</b>"
        ret += f"  label \"{name}\" as {label_name(hostname, port, connections.get("PROTO"))}\n"
        ret += f"  {connections.get("PORT_TYPE")} \" \" as {port_name(hostname, port, connections.get("PROTO"))}\n"
        _conns.append((f"{label_name(hostname, port, connections.get("PROTO"))}"
                           f"{connection_type(connections, priority=2)}"
                           f"{port_name(hostname, port, connections.get("PROTO"))}"))

    return ret


def end_unknown_node(hostname, server):
    ''' How to end an unknown node '''

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

    if conn.get("PROTO") not in ("tcp","tcp6",):
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
    ''' How to start a connection '''

    connections = []

    local_port = conn.get("LOCAL_PORT")

    connections.append((f"{arg_name(hostname, proc, args)}"
                        f"{connection_type(conn, priority=2)}"
                        f"{label_name(hostname, local_port, conn.get("PROTO"))}"))

    for remote_host in conn.get("REMOTE_HOST"):
        if (remote_port := conn.get("REMOTE_PORT")) not in ('*', '0'):
            connections.append((f"{port_name(hostname, local_port, conn.get("PROTO"))}"
                                f"{connection_type(conn, priority=-1)}"
                                f"{port_name(remote_host, remote_port, conn.get("PROTO"))}"))

    return "\n".join(connections)


def end_connection(hostname, proc, args, conn):
    ''' How to end a connection '''

    return ""


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
    "   Solid:  Open, TCP\n"
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
                    no_connections = False
                    for remote_host in conn.get("REMOTE_HOST", []):
                        remote_process = []
                        remote_args = []
                        for c in SERVER.get(remote_host, {}).get("NETSTAT", {}).get(f"{conn.get("REMOTE_PORT")}_{conn.get("PROTO")}", []):
                            if not hostname in get_dns(hostname, c.get("REMOTE_HOST"), c.get("REMOTE_PORT"), c.get("PROTO")):
                                continue
                            remote_pid = c.get("PID", "")
                            remote_process.append(SERVER.get(remote_host, {}).get("PS", {}).get(remote_pid, {}).get("PROCESS"))
                            remote_args.append(SERVER.get(remote_host, {}).get("PS", {}).get(remote_pid, {}).get("ARGS"))
                        if len(remote_process) == 0:
                            row = [conn.get("PROTO"), conn.get("STATE"), hostname, conn.get("LOCAL_PORT"), proc, arg,
                                remote_host, conn.get("REMOTE_PORT"), "", ""]
                            csv_dump.append(row)
                        for (p, a) in zip(remote_process, remote_args):
                            row = [conn.get("PROTO"), conn.get("STATE"), hostname, conn.get("LOCAL_PORT"), proc, arg,
                                remote_host, conn.get("REMOTE_PORT"), p, a]
                            csv_dump.append(row)
            if no_connections:
                row = ["", "", hostname, "", proc, arg, "", "", "", ""]
                csv_dump.append(row)

    csv_file = f"{".".join(GLOBALS.get("OUT_FILE").split(".")[:-1])}.csv"
    with open(csv_file, "w", encoding="utf-8", newline='') as fout:
        csv_writer = csv.writer(fout, quoting=csv.QUOTE_ALL)
        csv_writer.writerows(csv_dump)


def build_puml():
    ''' Runs plantuml.jar '''

    if os.path.isfile("plantuml.jar"):
        print("Generating diagram with PlantUML")
        subprocess.run(["java", "-jar", "plantuml.jar", GLOBALS.get("OUT_FILE"), "-tsvg"])
    else:
        print("Failed to find 'plantuml.jar' in current directory. Not generating diagram")


if __name__ == "__main__":
    # Run it
    parser = argparse.ArgumentParser("port_mapper.py")
    parser.add_argument("-i", help=f"Input directory. Default is '{GLOBALS.get("IN_DIR")}'", default=GLOBALS.get("IN_DIR"))
    parser.add_argument("-o", help=f"Output file. Default is '{GLOBALS.get("OUT_FILE")}'", default=GLOBALS.get("OUT_FILE"))
    parser.add_argument("-c", help=f"Include closed connections. Default is False", action="store_true", default=False)
    parser.add_argument("-x", help=f"Processes to exclude. Default is '{GLOBALS.get("EXCLUDE_FILE")}'", default=GLOBALS.get("EXCLUDE_FILE"))
    pargs = parser.parse_args()

    main(pargs)
