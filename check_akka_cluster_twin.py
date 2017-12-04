#!/usr/bin/env python
"""
This is a Nagios|Icinga-compatible check for Akka cluster
"""
import argparse
import logging
import pprint
import re
import sys
import jpype
import yaml
from enum import Enum
from jpype import java, javax


class NagiosStatus(Enum):
    """
    This is a small convenience enum to hold all Nagios status codes together
    """
    nagios_ok = 0
    nagios_warn = 1
    nagios_crit = 2
    nagios_unk = 3


NAGIOS_MESSAGES = {
    NagiosStatus.nagios_ok: 'OK',
    NagiosStatus.nagios_warn: 'WARN',
    NagiosStatus.nagios_crit: 'CRIT',
    NagiosStatus.nagios_unk: 'UNKNOWN'
}

# These are formal requirements for a proper library call
# However, this can be changed somewhen in the future
USER = 'dummy_user'
PASS = 'dummy_password'
# JVM paths may be different depending on whether JDK or JRE is installed:
# JDK
# JVM_PATH = '/usr/lib/jdk/jre/lib/amd64/server/libjvm.so'
# JRE
JVM_PATH = '/usr/lib/jre/lib/amd64/server/libjvm.so'
# LFS
STATUS_PATH_PREFIX = '/tmp'
LOG_FILENAME = 'check_akka_cluster%s.log'


def parse_parameters():
    """Parse command-line parameters

    Parse command-line parameters, check if all requirements
    are met and provide defaults as needed


    :rtype: namespace
    :return: contains all parameters within:
    """
    # Provide some defaults:
    # -s, --size = rs (number of cluster nodes as it should be)
    # -n, --nodes = e-akclust-01:9191 (list of host:port pairs to talk to)
    # -w, --warn = 1 (number of nodes to exit with "warning" status)
    # -c, --crit = 2 (number of nodes to exit with "critical" status)
    # -i, --id = ClusterSystem (cluster name as it is reported by cluster nodes)
    # -f, --file = ./nodes.txt (filename to store nodes list to)
    p = argparse.ArgumentParser(
        description="This script polls Akka cluster nodes status and acts as a Nagios check")
    p.add_argument("-s", "--size", type=int, dest="clust_size",
                   help="number of cluster nodes", required=True)
    p.add_argument("-w", "--warn", type=int, dest="warn_thresh",
                   help="warning threshold node number", required=True)
    p.add_argument("-c", "--crit", type=int, dest="crit_thresh",
                   help="critical threshold node number", required=True)
    p.add_argument("-i", "--id", action='store', dest="clust_id",
                   help="cluster id as it is reported by cluster nodes", required=True)
    p.add_argument("-n", "--nodes", action='store', dest="nodelist",
                   help="sets list of nodes to poll", required=True)
    p.add_argument("-j", "--jvm_path", action='store', dest="jvm_path",
                   help="sets path to main JVM shared library libjvm.so")
    p.add_argument("--state_file", action='store', dest="state_file",
                   help="sets state file name")
    p.add_argument('--version', action='version', version='%(prog)s 0.1')
    p.set_defaults(state_file='ClusterSystemTWIN')
    # p.set_defaults(clust_size=23)
    # p.set_defaults(warn_thresh=1)
    # p.set_defaults(crit_thresh=2)
    # p.set_defaults(clust_id='ClusterSystem')
    # p.set_defaults(nodelist="%s:%i" % (HOST, PORT))
    p.set_defaults(jvm_path=JVM_PATH)
    return p.parse_args()


# noinspection PyBroadException
def start_jvm(path):
    """Load JVM library and start JVM

    :param str path: filesystem path to Java VM shared library (libjvm.so on Linux)
    :rtype: bool
    :return: **True** if success, **False** if failure
    """
    try:
        jpype.startJVM(path)
        return True
    except:
        return False


def poll_host(host, port):
    """
    :param str host: IP address or resolvable hostname
    :param str port: JMX port number to connect to
    :rtype: dict
    :return: data returned by JMX request
    """
    logging.debug('poll_host() started')
    uri = "service:jmx:rmi:///jndi/rmi://%s:%s/jmxrmi" % (host, port)
    jhash = java.util.HashMap()
    jarray = jpype.JArray(java.lang.String)([USER, PASS])
    jhash.put(javax.management.remote.JMXConnector.CREDENTIALS, jarray)
    jmxurl = javax.management.remote.JMXServiceURL(uri)
    jmxsoc = javax.management.remote.JMXConnectorFactory.connect(jmxurl, jhash)
    connection = jmxsoc.getMBeanServerConnection()
    jmxobject = "akka:type=Cluster"
    attribute = "ClusterStatus"
    attr = connection.getAttribute(javax.management.ObjectName(jmxobject), attribute)
    z = yaml.safe_load(attr)
    logging.debug(pprint.pformat(z))
    # pprint.pprint(z)
    logging.debug('poll_host() finished')
    return z


def return_offline_nodes(inp):
    """ Iterate through input list and yield offline nodes list if found (empty list otherwise)

    :param dict inp: source dict to iterate
    :return: resulting list
    :rtype: list

    """
    res = list()
    for m in inp['members']:
        if m['status'] != 'Up':
            res.append(m['hostname'])
    return res


def parse_hostname(hostname):
    """Tear hostname into pieces retrieveing some useful info.

    Typical hostname looks like "host-01.domainname.example.com", so this
    will return a dict.

    :param str hostname: hostname
    :rtype: dict
    :return: [hostname_base: "host",
     hostname_number: "01",
     hostname_domain: "domainname.example.com"]
                  

    """
    tmp = re.search('^(\w-\w+-)(\d+)\.(.+)$', hostname)
    res = dict(hostname_base=tmp.group(1), hostname_number=tmp.group(2), hostname_domain=tmp.group(3))
    return res


def parse_akka_name(akka_name):
    # Input data is as follows:
    # 'akka.tcp://cluster_id@host-01.domainname.example.com:89123',
    """ Tear akka name into pieces retrieving some useful info from it.

    :rtype: dict
    :return: [clust_id: "cluster_id",
     hostname: "host-01.domainname.example.com",
     port_number: "89123"]
    :param str akka_name: cluster member name formatted as \"akka.tcp://cluster_id@host-01.domainname.example.com:89123\"
    """
    tmp = re.search('^akka\.tcp://(.+)@(.+):(\d+)$', akka_name)
    res = dict(clust_id=tmp.group(1), hostname=tmp.group(2), port_number=tmp.group(3))
    tmp2 = parse_hostname(res['hostname'])
    res.update(tmp2)
    return res


# noinspection PyBroadException
def poll_cluster(p):
    """Poll cluster set by CLI params passed in p.

    :rtype: int, str, list, list, dict, set of str
    :param Namespace p: contains all command-line parameters
    :return: *res_status*:check status code,

      *res_desc*:its text description,

      *reachable*:list of reachable nodes,

      *unreachable*:list of unreachable nodes,

      *statuses*: statuses of latter nodes,

      *clusters*: set of cluster IDs
    """
    logging.debug('poll_cluster() started')
    clusters = set()
    nodes_by_clusters = dict()
    live_node_count = 0
    res_status = NagiosStatus.nagios_crit
    res_desc = "No accessible hosts"
    param_nodelist = p.nodelist.split(',')
    for curr_node in param_nodelist:
        reachable = list()
        unreachable = list()
        statuses = dict()
        try:
            node_hostname, node_portnumber = curr_node.split(':')
        except ValueError:
            logging.info('Wrong node list element format')
            res_desc = "Wrong node list element format (expected FQDN:port)"
            res_status = NagiosStatus.nagios_crit
            continue
        try:
            node_result = poll_host(node_hostname, node_portnumber)
            response_num_nodes = len(node_result['members'])
        except:
            logging.info('host %s did not answer on port %s' % (node_hostname, node_portnumber))
            # well, this node does not respond - let's continue with another one
            continue
        # If given node sees self only, then let's skip it
        if response_num_nodes == 1:
            res_desc = "No cluster-belonging nodes found at host %s, port %s, skipping to next node " % \
                       (node_hostname, node_portnumber)
            res_status = NagiosStatus.nagios_crit
            continue
            # tmp = node_result['self-address']
            # curr_node_data = parse_akka_name(tmp)
        # There is no usage at the moment being for these data
        logging.info('Got response from %s:%s' % (node_hostname, node_portnumber))
        logging.info('%d nodes found in the response' % response_num_nodes)
        live_node_count = 0
        logging.debug('Starting iteration over node_result[\'members\']')
        for n in node_result['members']:
            node_data = parse_akka_name(n['address'])
            full_cluster_id = "%s_%s" % (node_data['clust_id'], node_data['port_number'])
            clusters.add(full_cluster_id)
            if full_cluster_id in nodes_by_clusters.keys():
                nodes_by_clusters[full_cluster_id] += 1
            else:
                nodes_by_clusters[full_cluster_id] = 1
            # Here we save node statuses in separate dict
            statuses[node_data['hostname']] = n['status']
            # Here we check that node belongs to proper ClusterId
            if (node_data['clust_id'] == p.clust_id) and (n['status'] == 'Up'):
                reachable.append(node_data['hostname'])
                live_node_count += 1
            if (node_data['clust_id'] == p.clust_id) and (n['status'] != 'Up'):
                unreachable.append(node_data['hostname'])
        if live_node_count > p.clust_size:
            logging.info(
                'All nodes are up. '
                'Node number %d exceeds cluster size %d (??!!) '
                'Please check the parameters in Nagios configuration!' % (live_node_count,p.clust_size))
            # res_status = NagiosStatus.nagios_warn
            res_status = NagiosStatus.nagios_ok
            res_desc = 'All nodes are up, but node number exceeds cluster size'
            break
        elif live_node_count == p.clust_size:
            logging.info('All nodes are up')
            res_status = NagiosStatus.nagios_ok
            res_desc = 'All nodes are up'
            break
            # Check if we have faced split-brain
        res_desc = 'Some nodes are offline'
        if live_node_count <= p.clust_size // 2:
            res_desc += '\nAttention required: possible cluster split-brain condition!'
        if len(clusters) == 2:
            # only for exactly two clusters
            full_node_number = 0
            for v in nodes_by_clusters.values():
                full_node_number += v
            if p.clust_size == full_node_number:
                res_status = NagiosStatus.nagios_warn
                res_desc += 'It seems like a deployment is going.\nSome nodes have been switched to a new cluster'
            else:
                logging.debug(pprint.pformat(nodes_by_clusters))
        if (p.clust_size - live_node_count) < p.warn_thresh:
            res_desc += 'This is how check thresholds are set'
            res_status = NagiosStatus.nagios_ok
            break
        elif (p.clust_size - live_node_count) >= p.warn_thresh and ((p.clust_size - live_node_count) < p.crit_thresh):
            res_status = NagiosStatus.nagios_warn
            break
        elif (p.clust_size - live_node_count) >= p.crit_thresh:
            res_status = NagiosStatus.nagios_crit
            break
    logging.debug('poll_cluster() finished')
    return res_status, res_desc, reachable, unreachable, statuses, clusters


def dedupe(l):
    """Deduplicate source list

    :param list l: Source list
    :rtype: list
    :return: Deduplicated list
    """
    seen = set()
    seen_add = seen.add
    return [x for x in l if not (x in seen or seen_add(x))]


def load_old_data(p):
    """Read data from previous state written earlier.

    :param namespace p: contains all command-line parameters
    :rtype: (list, list, list)
    :return: *reachable* : list of reachable nodes,

      *unreachable*: list of unreachable nodes,

      *ref_nodelist*: reference list of reachable nodes
    """
    filename = "%s/check_akka_cluster-%s.yml" % (STATUS_PATH_PREFIX, p.state_file)
    with open(filename, 'r') as yaml_file:
        r, u, ref_nodelist = yaml.safe_load(yaml_file)
    reachable = dedupe(r)
    unreachable = dedupe(u)
    logging.debug('reachable node list:\n%s' % pprint.pformat(reachable))
    logging.debug('unreachable node list:\n%s' % pprint.pformat(unreachable))
    logging.debug('reference node list:\n%s' % pprint.pformat(ref_nodelist))
    return reachable, unreachable, ref_nodelist


def prepare_node_report(reachable, unreachable, statuses):
    """Compile string list containing current cluster status report.

    :param list reachable: list of reachable nodes
    :param list unreachable: list of unreachable nodes
    :param dict statuses: contains node names as keys and their status value as values
    :return: list of strings containing report about current cluster state
    :rtype: list
    """
    logging.debug('prepare_node_report() started')
    res = list()
    res.append('\nCurrent status report')
    res.append('Good nodes (%s total):' % (len(reachable)))
    for i in reachable:
        res.append("%s" % i)
    res.append('Non-good nodes (%s total):' % (len(unreachable)))
    for i in unreachable:
        node_status = statuses[i]
        res.append("%s [%s]" % (i, node_status))
    logging.debug('prepare_node_report() finished')
    return res


def write_new_data(p, reachable, unreachable, check_data, statuses, ref_nodelist):
    """Write reachable and unreachable node lists to YaML file.

    :param ref_nodelist: nodelist serving as a comparision reference on evaluating cluster health
    :param namespace p: contains all command-line parameters
    :param list reachable: list of reachable nodes
    :param list unreachable: list of unreachable nodes
    :param list check_data: pre-compiled node status report
    :param dict statuses: status list for unreachable nodes
    :return: nothing
    """
    logging.debug('write_new_data() started')
    filename = "%s/check_akka_cluster-%s.yml" % (STATUS_PATH_PREFIX, p.state_file)
    try:
        with open(filename, 'w') as yaml_file:
            yaml.safe_dump_all([(reachable, unreachable, ref_nodelist)], yaml_file)
    except IOError as E:
        logging.error('Could not open %s: %s. Please check file access rights.' % (filename, str(E)))
    if check_data is None:
        node_list = prepare_node_report(reachable, unreachable, statuses)
    else:
        node_list = check_data
    filename = "%s/check_akka_cluster-%s.last" % (STATUS_PATH_PREFIX, p.state_file)
    try:
        with open(filename, "w") as text_file:
            for i in node_list:
                text_file.writelines("%s\n" % i)
    except IOError as E:
        logging.error('Could not open %s: %s. Please check file access rights.' % (filename, str(E)))
    logging.debug('write_new_data() finished')


def compare_lists(reach, old_reach):
    """
    Compare two reachable node lists and compile report describing differences.

    :param list of str old_reach: list of reachable nodes from previous run
    :param list reach: list of reachable nodes from current run
    :return: list containing changes between two reachable node lists
    :rtype: list of str
    """
    logging.debug('compare_lists() started')
    res = list()
    tmp_list1 = reach[:]
    tmp_list2 = old_reach[:]
    for i in reach:
        if i in tmp_list2:
            tmp_list2.remove(i)
    for i in old_reach:
        if i in tmp_list1:
            tmp_list1.remove(i)
    if (len(tmp_list1) + len(tmp_list2)) == 0:
        # Lists are the same
        return res
    for i in tmp_list1:
        res.append('Node %s has gone ONLINE' % i)
    for i in tmp_list2:
        res.append('Node %s has gone OFFLINE' % i)
    logging.debug('compare_lists() finished')
    return res


def configure_logging(log_id=None):
    """Set up logging

    :param str log_id: this is an optional parameter that allows to differ log filenames between separate checks
    :return: nothing
    """
    if log_id is None:
        full_log_filename=LOG_FILENAME % ''
    else:
        full_log_filename=LOG_FILENAME % ('_' + log_id)
    logging.basicConfig(filename="%s/%s" % (STATUS_PATH_PREFIX,
                                            full_log_filename),
                        level=logging.DEBUG,
                        format='%(asctime)s: [line %(lineno)-4s] %(levelname)-8s %(message)s',
                        datefmt='%m-%d-%Y %H:%M:%S')
    logging.debug('configure_logging() was called and has set the logging up')


def prepare_changes_report(changes):
    """Convert separate header and list of strings to the single string

    :param list of str changes: previously compiled report
    :return: all strings from the report are glued
    :rtype: str
    """
    logging.debug('prepare_changes_report() started')
    res = "\n\nChanges list:\n" + "\n".join(changes)
    logging.debug('prepare_changes_report() finished')
    return res


def prepare_misses_report(check_status, ref_list, reachable_list):
    """

    :param check_status:
    :param ref_list:
    :param reachable_list:
    :return:
    """
    logging.debug('prepare_misses_report() started')
    if check_status != NagiosStatus.nagios_ok:
        # Compare reachable node list with reference and make a list out of it
        tmp_list = list(x for x in ref_list if x not in reachable_list)
        tmp_list.insert(0, "\nMissing nodes are:")
        res = "\n".join(tmp_list[0:])
    else:
        res = ""
    logging.debug('prepare_misses_report() finished')
    return res


def main():
    """ Execute check

    """
    try:
        params = parse_parameters()
    except Exception as E:
        output_format = "Could not parse parameters:\n%s"
        output_args = ' '.join(sys.argv[1:]) + str(E)
        res_status = NagiosStatus.nagios_crit
    else:
        configure_logging(params.state_file)
        if start_jvm(params.jvm_path):
            # This function does all dirty work and differs for simple
            # and cluster-split-checking version
            res_status, res_desc, reachable, unreachable, statuses, clusters = poll_cluster(params)
            # And here's just some housekeeping
            try:
                (old_reachable, old_unreachable, ref_nodelist) = load_old_data(params)
                logging.debug('load_old_data() completed')
            except Exception as E:
                # We could not read previous data, so any exceptions will be swallowed
                old_reachable = list()
                ref_nodelist = ()
                logging.debug(
                    'load_old_data() failed '
                    'with message %s, so at least'
                    ' one of the old_reachable/old_unreachable'
                    '/ref_nodelist lists is empty' % E)
            node_report = prepare_node_report(reachable, unreachable, statuses)
            check_output = "\n".join(node_report[0:])
            # Do we have any changes?
            reachable_list_changes = compare_lists(reachable, old_reachable)
            if len(reachable_list_changes) != 0:
                # Yes, there are changes in reachable nodes
                if res_status == NagiosStatus.nagios_ok:
                    tmp_list = reachable
                else:
                    tmp_list = ref_nodelist
                write_new_data(params, reachable, unreachable, node_report, statuses, tmp_list)
                changed_sign = " [CHANGED]"
                check_output += prepare_changes_report(reachable_list_changes[0:])
            else:
                # No changes were detected
                logging.debug('write_new_data() skipped - no changes detected')
                changed_sign = ''
            check_output += prepare_misses_report(res_status, ref_nodelist, reachable)
            output_format = "%s:%s Cluster size:%s, Warn:%s, " \
                            "Crit:%s\n%s\n%s"
            output_args = (
                NAGIOS_MESSAGES[res_status], changed_sign, len(reachable), params.warn_thresh, params.crit_thresh,
                res_desc, check_output)
            logging.debug('output_format and output_args are ready')
            logging.debug('variables in the end:')
            logging.debug("res_status=%s" % pprint.pformat(res_status))
            logging.debug("res_desc=%s" % pprint.pformat(res_desc))
            for value in ('params', 'old_reachable', 'old_unreachable', 'reachable', 'unreachable'):
                for i in pprint.pformat(eval(value)).split('\n'):
                    logging.debug("%s: %s" % (value, i))
        else:
            # Say that we were unsuccessful
            res_status = NagiosStatus.nagios_unk
            output_format = "%s: Could not load JVM shared library, please check library path %s"
            output_args = (NAGIOS_MESSAGES[res_status], JVM_PATH)
    res_msg = output_format % output_args
    logging.debug("res_msg: %s" % res_msg)
    print(res_msg)
    exit(res_status)


if __name__ == '__main__':
    main()
