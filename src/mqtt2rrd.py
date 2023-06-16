#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2014 David Irvine
#
# This file is part of MQTT2RRD
#
# MQTT2RRD is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MQTT2RRD is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MQTT2RRD.  If not, see "http://www.gnu.org/licenses/".
#
# Modified by Christopher McAvaney (christopher.mcavaney@gmail.com) 2020
# https://github.com/clmcavaney/MQTT2RRD.git
#
import sys, os, argparse, atexit, time, logging, configparser, grp, pwd, getpass, json
from signal import SIGTERM

import paho.mqtt.client as mqtt
import rrdtool

logger=logging.getLogger("MQTT2RRD")

config = configparser.RawConfigParser()


def get_config_item(section, name, default):
    """
    Gets an item from the config file, setting the default value if not found.
    """
    try:
        value = config.get(section, name)
    except:
        value = default
    return value


def extract_float(pl, json_key = False):
    data_value = None

    # if a json_key is specified, there is a pretty good change that the payload is a json string
    if json_key is not False:
        data_pl = json.loads(pl)[json_key]
    else:
        data_pl = pl

    """
    Tries to find a float value in the message payload.
    """
    try:
        data_value = float(data_pl)
    except ValueError:
        pass

    if data_value is None:
        try:
            data_value = float(data_pl.decode().split(" ")[0])
        except ValueError:
            pass

    """
    try:
        resp = json.loads(pl)
        if 'temp' in resp:
            return float(resp['temp'])
        elif 'temperature' in resp:
            return float(resp['temperature'])
    except ( ValueError, KeyError ):
        pass

    try:
        resp = json.loads(pl)
        return float(resp['humidity'])
    except ( ValueError, KeyError ):
        pass
    """

    return data_value


# update the RRD file for the received message
# if the RRD file doesn't exist, then create it
def update_rrd(msg, ts, pl, json_key = False):
    global args

    if not args.no_rrd_updates:
        components = msg.topic.split("/")
        file_name = components.pop()

        # at this point the file name will need the json key appended (if there is a json key in the config)
        if json_key is not False:
            file_name = "{}-{}".format(file_name, json_key)
        
        info_file_name = "%s.info" % file_name
        file_name = "%s.rrd" % file_name

        dir_name = get_config_item("daemon","data_dir","/var/lib/mqtt2rrd/")
        while (len(components) > 0):
            dir_name = os.path.join(dir_name, components.pop(0))
            if not os.path.isdir(dir_name):
                os.mkdir(dir_name)
                logger.debug("Created directory: %s for topic: %s" % (dir_name, msg.topic))
    
        # if the topic name has '/' or '.' in it, replace with an underscore (_)
        file_path = os.path.join(dir_name, file_name)
        graph_name = msg.topic.replace("/", "_")
        graph_name = graph_name.replace(".", "_")
        # append the json key to the topic
        # e.g. if graph_name is "homie/tsl/laundry/json" and json_key is "humidity"
        # graph_name would be:
        # homie/tsl/laundry/json_humidity
        if json_key is not False:
            graph_name = f"{graph_name}_{json_key}"
        if len(graph_name) > 19:
            graph_name = graph_name[:19]

        # take the data source name from the config (if defined) otherwise the truncated graph_name will be used
        ds_conf = get_config_item(msg.topic, "ds", graph_name)
        if json_key is not False:
            ds_conf = f"{ds_conf}_{json_key}"
        if len(ds_conf) > 19:
            ds_conf = ds_conf[:19]
        logger.debug('ds_conf == {}'.format(ds_conf))

        # if the RRD file doesn't exist, create it
        if not os.path.exists(file_path):
            try:
                step = get_config_item(msg.topic, "step", 60)
                hb_conf = get_config_item(msg.topic, "hb", False)
                # default heartbeat is 2 x step value
                if hb_conf is False:
                    hb = 2*int(step)
                else:
                    hb = int(hb_conf)
                
                ds = "DS:%s:GAUGE:%d:U:U" % (ds_conf, hb)

                # Create the info file
                friendly_name = get_config_item(msg.topic, "friendly_name", msg.topic).strip('"')
                # append the json_key (e.g. temperature or humidity or whatever)
                if json_key is not False:
                    friendly_name = f"{friendly_name} {json_key}"
                info={
                    'topic':msg.topic,
                    'created':time.time(),
                    'friendly_name': friendly_name,
                    'ds':ds_conf
                }
                # add the json_key if provided
                if json_key is not False:
                    info['json_key'] = json_key

                info_fpath = os.path.join(dir_name, info_file_name)
                f=open(info_fpath, "w")
                json.dump(info, f)
                f.close()
                # Create the RRD file
                RRAstr = get_config_item(
                    msg.topic,
                    "archives",
                    "RRA:AVERAGE:0.5:2:30,RRA:AVERAGE:0.5:5:288,RRA:AVERAGE:0.5:30:336,RRA:AVERAGE:0.5:60:1488,RRA:AVERAGE:0.5:720:744,RRA:AVERAGE:0.5:1440:265"
                )

                RRAs = []
                for i in RRAstr.split(","):
                    i = i.lstrip(" ")
                    i = i.rstrip(" ")
                    i = str(i)
                    RRAs.append(i)

                logger.info("Creating RRD file: %s for topic: %s" % (file_path, msg.topic))
                rrdtool.create(str(file_path), "--step", str(step), "--start", "0", ds, *RRAs)

            except rrdtool.OperationalError as e:
                logger.error("Could not create RRD for topic: %s: %s" % (ds, str(e)))
        try:
            logger.info("Updating: %s with value: %d:%s" % (file_path, ts, pl))
            rrdtool.update(str(file_path), str("%d:%f" % (ts, pl)))
        except rrdtool.OperationalError as e:
            logger.error("Could not log value: %s to RRD %s for topic: %s: %s" % (pl, file_path, msg.topic, str(e)))
    else:
        logger.info("No RRD updates requested")


####
#
#  Sub Command Handlers, called for each command specified in arg parser config
#
####
def start(args, daemon):
    """
        Starts logging, either as a daemon or in the foreground.
    """
    # Check the data directory exists
    data_dir = get_config_item("daemon", "data_dir", "/var/lib/mqtt2rrd", )
    if not os.path.isdir(data_dir):
        logger.critical(
            "%s: Error: data directory %s does not exist or is not a directory\n" % (sys.argv[0], data_dir))
        sys.exit(1)

    if args.no_daemon:
        try:
            run(args)
        except (KeyboardInterrupt, SystemExit):
            print("Quitting.")
    else:
        daemon.start(args)

def stop(args, daemon):
    daemon.stop()


def restart(args, daemon):
    daemon.restart(args, daemon)


def run(args):
    """
    Initiates the MQTT connection, and starts the main loop
    Is called by either the daemon.start() method, or the start function
    if the no-daemon option is specified.
    """
    while(True):
        try:
            logger.debug("Entering Loop")
            client = mqtt.Client(get_config_item("mqtt", "client_id", "MQTT2RRD Client"), protocol=eval(get_config_item("mqtt", "protocol", mqtt.MQTTv311)))
            client.on_message = on_message
            client.on_connect = on_connect
            client.on_log = on_log
            client.enable_logger(logger)

            if get_config_item("mqtt", "username", None):
                client.username_pw_set(
                    get_config_item("mqtt", "username", ""),
                    get_config_item("mqtt", "password", ""),
                )
            logger.debug("Attempting to connect to server: %s:%s" % (get_config_item("mqtt", "hostname", "localhost"), get_config_item("mqtt", "port", 1833),))
            client.connect(
                host=get_config_item("mqtt", "hostname", "localhost"),
                port=int(get_config_item("mqtt", "port", 1883)),
                keepalive=int(get_config_item("mqtt", "keepalive", 60)),
            )
            logger.info("Connected: %s:%s" % (get_config_item("mqtt", "hostname", "localhost"), get_config_item("mqtt", "port", 1833),))
            client.loop_forever()
        except Exception as e:
            logging.critical("FAIL: %s" % str(e))
            time.sleep(30) # 30 second wait


####
#
# MQTT Callback handlers
#
####
def on_connect(client, userdata, flags, rc):
    logger.info("Connected to server.")
    subs = get_config_item("mqtt", "subscriptions", "#")
    for i in subs.split(","):
        try:
            logger.info("Subscribing to topic: %s" % i)
            resp = client.subscribe(i)
            logger.info("Subscribed to topic: %s" % i)
        except Exception as e:
            logging.critical("FAIL: %s" % str(e))
    logger.info("end of connect")

def on_message(mosq, obj, msg):
    global args

    logger.debug("Message received on topic: %s with payload: %s." % (msg.topic, msg.payload))

    # Get the time stamp - that can be in the json payload. If not, use the time this message is received
    # need to extract the appropriate value from the payload
    try:
        resp = json.loads(msg.payload)
    except ValueError:
        logger.debug("Decoding JSON has failed: %s" % msg.payload)
        return

    # If no ts in payload, then use current time
    if "ts" in resp:
        ts = resp['ts']
    else:
        ts = int(time.time())
    

    # have to check if there is a json_keys attribute of the configuration for the "topic" (aka subscription)
    json_keys = get_config_item(msg.topic, "json_keys", False)
    logger.debug('json_keys == {} and {}'.format(json_keys, json_keys.split(',')))
    if json_keys is not False:
        # iterate over the keys
        for key in json_keys.split(','):
            pl = extract_float(msg.payload, key)
            if pl == None:
                logger.debug("Unable to get float from payload (for key {}): {}".format(key, msg.payload))
                return
            logger.info("Message received on topic " + msg.topic + " with QoS " + str(
                msg.qos) + " and payload %.2f " % pl)

            logger.info('updating RRD file')
            update_rrd(msg, ts, pl, key)

    else:
        # original method
        pl = extract_float(msg.payload)
        """
        if 'temp' in resp:
            pl = extract_float(resp['temp'])
        elif 'humidity' in resp:
            pl = extract_float(resp['humidity'])
        else:
            logger.debug("Unable to get float from payload: %s" % msg.payload)
            return
        """

        if pl == None:
            logger.debug("Unable to get float from payload: %s" % msg.payload)
            return

        logger.info("Message received on topic " + msg.topic + " with QoS " + str(
            msg.qos) + " and payload %f " % pl)

        update_rrd(msg, ts, pl)


def on_log(client, userdata, level, buf):
    print("log: lvl({0}): {1}".format(hex(level), buf))


######
#
# Background process handlers
#
######
class Daemon:
    """
    A generic daemon class.

    Usage: subclass the Daemon class and override the run() method

    Used with permission from Sander Marechal:
    http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/

    """

    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(self.stdin, 'r')
        so = open(self.stdout, 'a+')
        se = open(self.stderr, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        open(self.pidfile, 'w+').write("%s\n" % pid)

    def delpid(self):
        os.remove(self.pidfile)

    def start(self, *args, **kwargs):
        """
        Start the daemon
        """
        # Check for a pidfile to see if the daemon already runs
        try:
            pf = open(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            message = "pidfile %s already exist. Daemon already running?\n"
            logger.error(message % self.pidfile)
            sys.exit(1)
        # Start the daemon
        logger.debug("Daemonizing")
        self.daemonize()
        logger.debug("Running")
        self.run(*args, **kwargs)

    def stop(self):
        logger.debug("Stopping Daemon")
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        try:
            pf = open(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            message = "pidfile %s does not exist. Daemon not running?\n"
            logger.info(message % self.pidfile)
            return  # not an error in a restart

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                sys.exit(1)

    def restart(self, *args, **kwargs):
        """
        Restart the daemon
        """
        self.stop()
        self.start(*args, **kwargs)

    def run(self, *args, **kwargs):
        """
        You should override this method when you subclass Daemon. It will be called after the process has been
        daemonized by start() or restart().
        """


class MQTTDaemon(Daemon):
    def run(self, *args, **kwargs):
        run(*args, **kwargs)


parser = argparse.ArgumentParser()
parser.add_argument("--config_file", help="The location of the config file (default: either /etc/mqtt2rrd.conf or ~/.mqtt2rrd.conf", type=str, default="")

parser_subparsers = parser.add_subparsers(title='subcommands', description='Valid Commands',
                                   help='The following commands are available', dest='cmd')
parser_subparsers.required = True

stop_parser = parser_subparsers.add_parser('stop')
stop_parser.set_defaults(func=stop)
#stop_parser.add_argument("--config_file", help="The location of the config file", type=str, default="")

restart_parser = parser_subparsers.add_parser('restart')
#restart_parser.add_argument("--config_file", help="The location of the config file", type=str, default="")
restart_parser.set_defaults(func=restart)

start_parser = parser_subparsers.add_parser('start')
start_parser.set_defaults(func=start)
#start_parser.add_argument("--config_file", help="The location of the config file", type=str, default="")
start_parser.add_argument("--no_daemon", help="Do not spawn a daemon, stay in the foreground",
                          action="store_true", default=False)
start_parser.add_argument("--no_rrd_updates", help="Only show output of MQTT topics, don't perform any RRD operations",
                          action="store_true", default=False)

args = parser.parse_args()

# Load configuration information
if len(args.config_file) > 0:
    config.read_file(open(args.config_file))
else:
    default_conf_files = ['/etc/mqtt2rrd.conf', os.path.expanduser('~/.mqtt2rrd.conf')]
    dataset = config.read(default_conf_files)
    if len(dataset) == 0:
        raise ValueError("Failed to open any conf file")
        sys.exit(1)


formatter = logging.Formatter('%(asctime)s: %(levelname)s: %(message)s')

logger.setLevel(get_config_item("logging", "log_level", "DEBUG"))
lf=get_config_item("logging", "log_file", None)
if lf:
    fh = logging.FileHandler(lf)
    fh.setLevel(get_config_item("logging", "log_level", "DEBUG"))
    fh.setFormatter(formatter)
    logger.addHandler(fh)
ch = logging.StreamHandler()
ch.setLevel(get_config_item("logging", "log_level", "DEBUG"))
ch.setFormatter(formatter)
logger.addHandler(ch)



# Change to correct user if running as root.
user = get_config_item("daemon", "user", None)
group = get_config_item("daemon", "group", None)

if user and group and os.getuid() == 0:
    user = pwd.getpwnam(user).pw_uid
    group = grp.getgrnam(group).gr_gid

    os.setgid(group)
    os.setuid(user)


logger.info("Running as: %s" % getpass.getuser())

daemon = MQTTDaemon(get_config_item("daemon","pid_file","/var/run/mqtt2rrd.pid"))
logger.debug("Setup Daemon")
args.func(args, daemon)

# vim: expandtab
# END OF FILE
