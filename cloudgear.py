#! /usr/bin/python
import sys
import os
import time
import fcntl
import struct
import socket
import subprocess

# These are module names which are not installed by default.
# These modules will be loaded later after downloading
iniparse = None
psutil = None

mysql_password = "secret"

def kill_process(process_name):
    for proc in psutil.process_iter():
        if proc.name == process_name:
            proc.kill()

def get_ip_address(ifname):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return socket.inet_ntoa(fcntl.ioctl(s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', ifname[:15])
            )[20:24])
        except Exception:
            print "Cannot get IP Address for Interface %s" % ifname
            sys.exit(1)

def delete_file(file_path):
    if os.path.isfile(file_path):
        os.remove(file_path)
    else:
        print("Error: %s file not found" % file_path)

def write_to_file(file_path, content):
    open(file_path, "a").write(content)

def add_to_conf(conf_file, section, param, val):
    config = iniparse.ConfigParser()
    config.readfp(open(conf_file))
    if not config.has_section(section):
        config.add_section(section)
        val += '\n'
    config.set(section, param, val)
    with open(conf_file, 'w') as f:
        config.write(f)


def delete_from_conf(conf_file, section, param):
    config = iniparse.ConfigParser()
    config.readfp(open(conf_file))
    if param is None:
        config.remove_section(section)
    else:
        config.remove_option(section, param)
    with open(conf_file, 'w') as f:
        config.write(f)


def get_from_conf(conf_file, section, param):
    config = iniparse.ConfigParser()
    config.readfp(open(conf_file))
    if param is None:
        raise Exception("parameter missing")
    else:
        return config.get(section, param)

def print_format(string):
    print "+%s+" %("-" * len(string))
    print "|%s|" % string
    print "+%s+" %("-" * len(string))

def execute(command, display=False):
    print_format("Executing  :  %s " % command)
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if display:
        while True:
            nextline = process.stdout.readline()
            if nextline == '' and process.poll() != None:
                break
            sys.stdout.write(nextline)
            sys.stdout.flush()

        output, stderr = process.communicate()
        exitCode = process.returncode
    else:
        output, stderr = process.communicate()
        exitCode = process.returncode

    if (exitCode == 0):
        return output.strip()
    else:
        print "Error", stderr
        print "Failed to execute command %s" % command
        print exitCode, output
        raise Exception(output)


def execute_db_commnads(command):
    cmd = """mysql -uroot -p%s -e "%s" """ % (mysql_password, command)
    output = execute(cmd)
    return output


def initialize_system():
    if not os.geteuid() == 0:
        sys.exit('Please re-run the script with root user')

    execute("apt-get clean" , True)
    execute("apt-get autoclean -y" , True)
    execute("apt-get update -y" , True)
    execute("apt-get install ubuntu-cloud-keyring python-setuptools python-iniparse python-psutil -y", True)
    delete_file("/etc/apt/sources.list.d/grizzly.list")
    execute("echo deb http://ubuntu-cloud.archive.canonical.com/ubuntu precise-updates/grizzly main >> /etc/apt/sources.list.d/grizzly.list")
    execute("apt-get update -y", True)

    global iniparse
    if iniparse is None:
        iniparse = __import__('iniparse')

    global psutil
    if psutil is None:
        psutil = __import__('psutil')
#=================================================================================
#==================   Components Installation Starts Here ========================
#=================================================================================

ip_address = get_ip_address("eth0")

def install_rabbitmq():
    execute("apt-get install rabbitmq-server -y", True)
    execute("service rabbitmq-server restart", True)
    time.sleep(2)


def install_database():
    os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
    execute("apt-get install mysql-server python-mysqldb mysql-client-5.5 -y", True)
    execute("sed -i 's/127.0.0.1/0.0.0.0/g' /etc/mysql/my.cnf")
    execute("service mysql restart", True)
    time.sleep(2)
    try:
        execute("mysqladmin -u root password %s" % mysql_password)
    except Exception:
        print " Mysql Password already set as : %s " % mysql_password



def _create_keystone_users():
    os.environ['SERVICE_TOKEN'] = 'ADMINTOKEN'
    os.environ['SERVICE_ENDPOINT'] = 'http://127.0.0.1:35357/v2.0'
    os.environ['no_proxy'] = "localhost,127.0.0.1,%s" % ip_address

    #TODO(ish) : This is crude way of doing. Install keystone client and use that to create tenants, role etc
    admin_tenant = execute("keystone tenant-create --name admin --description 'Admin Tenant' --enabled true |grep ' id '|awk '{print $4}'")
    admin_user = execute("keystone user-create --tenant_id %s --name admin --pass secret --enabled true|grep ' id '|awk '{print $4}'" % admin_tenant)
    admin_role = execute("keystone role-create --name admin|grep ' id '|awk '{print $4}'")
    execute("keystone user-role-add --user_id %s --tenant_id %s --role_id %s" % (admin_user, admin_tenant, admin_role))


    service_tenant = execute("keystone tenant-create --name service --description 'Service Tenant' --enabled true |grep ' id '|awk '{print $4}'")


    #keystone
    keystone_service = execute("keystone service-create --name=keystone --type=identity --description='Keystone Identity Service'|grep ' id '|awk '{print $4}'")
    execute("keystone endpoint-create --region region --service_id=%s --publicurl=http://%s:5000/v2.0 --internalurl=http://127.0.0.1:5000/v2.0 --adminurl=http://127.0.0.1:35357/v2.0" % (keystone_service, ip_address))


    #Glance
    glance_user = execute("keystone user-create --tenant_id %s --name glance --pass glance --enabled true|grep ' id '|awk '{print $4}'" % service_tenant)
    execute("keystone user-role-add --user_id %s --tenant_id %s --role_id %s" % (glance_user, service_tenant, admin_role))

    glance_service = execute("keystone service-create --name=glance --type=image --description='Glance Image Service'|grep ' id '|awk '{print $4}'")
    execute("keystone endpoint-create --region region --service_id=%s --publicurl=http://%s:9292/v2 --internalurl=http://127.0.0.1:9292/v2 --adminurl=http://127.0.0.1:9292/v2" % (glance_service, ip_address))


    #nova
    nova_user = execute("keystone user-create --tenant_id %s --name nova --pass nova --enabled true|grep ' id '|awk '{print $4}'" % service_tenant)
    execute("keystone user-role-add --user_id %s --tenant_id %s --role_id %s" % (nova_user, service_tenant, admin_role))

    nova_service = execute("keystone service-create --name=nova --type=compute --description='Nova Compute Service'|grep ' id '|awk '{print $4}'")
    execute("keystone endpoint-create --region region --service_id=%s --publicurl='http://%s:8774/v2/$(tenant_id)s' --internalurl='http://127.0.0.1:8774/v2/$(tenant_id)s' --adminurl='http://127.0.0.1:8774/v2/$(tenant_id)s'" % (nova_service, ip_address))


    #quantum
    quantum_user = execute("keystone user-create --tenant_id %s --name quantum --pass quantum --enabled true|grep ' id '|awk '{print $4}'" % service_tenant)
    execute("keystone user-role-add --user_id %s --tenant_id %s --role_id %s" % (quantum_user, service_tenant, admin_role))

    quantum_service = execute("keystone service-create --name=quantum --type=network  --description='OpenStack Networking service'|grep ' id '|awk '{print $4}'")
    execute("keystone endpoint-create --region region --service_id=%s --publicurl=http://%s:9696/ --internalurl=http://127.0.0.1:9696/ --adminurl=http://127.0.0.1:9696/" % (quantum_service, ip_address))

    #write a rc file
    adminrc = "/root/adminrc"
    delete_file(adminrc)
    write_to_file(adminrc, "export OS_USERNAME=admin\n")
    write_to_file(adminrc, "export OS_PASSWORD=secret\n")
    write_to_file(adminrc, "export OS_TENANT_NAME=admin\n")
    write_to_file(adminrc, "export OS_AUTH_URL=http://127.0.0.1:5000/v2.0\n")



def install_and_configure_keystone():
    keystone_conf = "/etc/keystone/keystone.conf"

    execute_db_commnads("DROP DATABASE IF EXISTS keystone;")
    execute_db_commnads("CREATE DATABASE keystone;")
    execute_db_commnads("GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'%' IDENTIFIED BY 'keystone';")
    execute_db_commnads("GRANT ALL PRIVILEGES ON keystone.* TO 'keystone'@'localhost' IDENTIFIED BY 'keystone';")

    execute("apt-get install keystone -y", True)


    add_to_conf(keystone_conf, "DEFAULT", "admin_token", "ADMINTOKEN")
    add_to_conf(keystone_conf, "DEFAULT", "admin_port", 35357)
    add_to_conf(keystone_conf, "sql", "connection", "mysql://keystone:keystone@localhost/keystone")
    add_to_conf(keystone_conf, "signing", "token_format", "UUID")

    execute("keystone-manage db_sync")

    execute("service keystone restart", True)

    time.sleep(3)
    _create_keystone_users()



def install_and_configure_glance():
    glance_api_conf = "/etc/glance/glance-api.conf"
    glance_registry_conf = "/etc/glance/glance-registry.conf"
    glance_api_paste_conf = "/etc/glance/glance-api-paste.ini"
    glance_registry_paste_conf = "/etc/glance/glance-registry-paste.ini"

    execute_db_commnads("DROP DATABASE IF EXISTS glance;")
    execute_db_commnads("CREATE DATABASE glance;")
    execute_db_commnads("GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'%' IDENTIFIED BY 'glance';")
    execute_db_commnads("GRANT ALL PRIVILEGES ON glance.* TO 'glance'@'localhost' IDENTIFIED BY 'glance';")

    execute("apt-get install glance -y", True)


    add_to_conf(glance_api_paste_conf, "filter:authtoken", "auth_host", "127.0.0.1")
    add_to_conf(glance_api_paste_conf, "filter:authtoken", "auth_port", "35357")
    add_to_conf(glance_api_paste_conf, "filter:authtoken", "auth_protocol", "http")
    add_to_conf(glance_api_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
    add_to_conf(glance_api_paste_conf, "filter:authtoken", "admin_user", "glance")
    add_to_conf(glance_api_paste_conf, "filter:authtoken", "admin_password", "glance")


    add_to_conf(glance_registry_paste_conf, "filter:authtoken", "auth_host", "127.0.0.1")
    add_to_conf(glance_registry_paste_conf, "filter:authtoken", "auth_port", "35357")
    add_to_conf(glance_registry_paste_conf, "filter:authtoken", "auth_protocol", "http")
    add_to_conf(glance_registry_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
    add_to_conf(glance_registry_paste_conf, "filter:authtoken", "admin_user", "glance")
    add_to_conf(glance_registry_paste_conf, "filter:authtoken", "admin_password", "glance")


    add_to_conf(glance_api_conf, "DEFAULT", "sql_connection", "mysql://glance:glance@localhost/glance")
    add_to_conf(glance_api_conf, "paste_deploy", "flavor", "keystone")
    add_to_conf(glance_api_conf, "DEFAULT", "verbose", "true")
    add_to_conf(glance_api_conf, "DEFAULT", "debug", "true")


    add_to_conf(glance_registry_conf, "DEFAULT", "sql_connection", "mysql://glance:glance@localhost/glance")
    add_to_conf(glance_registry_conf, "paste_deploy", "flavor", "keystone")
    add_to_conf(glance_registry_conf, "DEFAULT", "verbose", "true")
    add_to_conf(glance_registry_conf, "DEFAULT", "debug", "true")

    execute("glance-manage db_sync")

    execute("service glance-api restart", True)
    execute("service glance-registry restart", True)




def install_and_configure_nova():
    nova_conf = "/etc/nova/nova.conf"
    nova_paste_conf = "/etc/nova/api-paste.ini"
    nova_compute_conf = "/etc/nova/nova-compute.conf"

    execute_db_commnads("DROP DATABASE IF EXISTS nova;")
    execute_db_commnads("CREATE DATABASE nova;")
    execute_db_commnads("GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'%' IDENTIFIED BY 'nova';")
    execute_db_commnads("GRANT ALL PRIVILEGES ON nova.* TO 'nova'@'localhost' IDENTIFIED BY 'nova';")

    execute("apt-get install kvm libvirt-bin -y")
    execute("apt-get install nova-api nova-cert nova-scheduler nova-conductor nova-compute-kvm novnc nova-consoleauth nova-novncproxy -y", True)


    add_to_conf(nova_paste_conf, "filter:authtoken", "auth_host", "127.0.0.1")
    add_to_conf(nova_paste_conf, "filter:authtoken", "auth_port", "35357")
    add_to_conf(nova_paste_conf, "filter:authtoken", "auth_protocol", "http")
    add_to_conf(nova_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
    add_to_conf(nova_paste_conf, "filter:authtoken", "admin_user", "nova")
    add_to_conf(nova_paste_conf, "filter:authtoken", "admin_password", "nova")


    add_to_conf(nova_conf, "DEFAULT", "logdir", "/var/log/nova")
    add_to_conf(nova_conf, "DEFAULT", "verbose", "true")
    add_to_conf(nova_conf, "DEFAULT", "debug", "true")
    add_to_conf(nova_conf, "DEFAULT", "lock_path", "/var/lib/nova")
    add_to_conf(nova_conf, "DEFAULT", "rabbit_host", "127.0.0.1")
    add_to_conf(nova_conf, "DEFAULT", "sql_connection", "mysql://nova:nova@localhost/nova")
    add_to_conf(nova_conf, "DEFAULT", "glance_api_servers", "127.0.0.1:9292")
    add_to_conf(nova_conf, "DEFAULT", "compute_driver", "libvirt.LibvirtDriver")
    add_to_conf(nova_conf, "DEFAULT", "dhcpbridge_flagfile", "/etc/nova/nova.conf")
    add_to_conf(nova_conf, "DEFAULT", "firewall_driver", "nova.virt.libvirt.firewall.IptablesFirewallDriver")
    add_to_conf(nova_conf, "DEFAULT", "root_helper", "sudo nova-rootwrap /etc/nova/rootwrap.conf")
    add_to_conf(nova_conf, "DEFAULT", "compute_driver", "libvirt.LibvirtDriver")
    add_to_conf(nova_conf, "DEFAULT", "auth_strategy", "keystone")
    add_to_conf(nova_conf, "DEFAULT", "novnc_enabled", "true")
    add_to_conf(nova_conf, "DEFAULT", "novncproxy_base_url", "http://%s:6080/vnc_auto.html" % ip_address)
    add_to_conf(nova_conf, "DEFAULT", "novncproxy_port", "6080")
    add_to_conf(nova_conf, "DEFAULT", "vncserver_proxyclient_address", ip_address)
    add_to_conf(nova_conf, "DEFAULT", "vncserver_listen", "0.0.0.0")
    add_to_conf(nova_conf, "DEFAULT", "network_api_class", "nova.network.quantumv2.api.API")
    add_to_conf(nova_conf, "DEFAULT", "quantum_admin_username", "quantum")
    add_to_conf(nova_conf, "DEFAULT", "quantum_admin_password", "quantum")
    add_to_conf(nova_conf, "DEFAULT", "quantum_admin_tenant_name", "service")
    add_to_conf(nova_conf, "DEFAULT", "quantum_admin_auth_url", "http://127.0.0.1:5000/v2.0/")
    add_to_conf(nova_conf, "DEFAULT", "quantum_auth_strategy", "keystone")
    add_to_conf(nova_conf, "DEFAULT", "quantum_url", "http://127.0.0.1:9696/")
    add_to_conf(nova_conf, "DEFAULT", "linuxnet_interface_driver", "nova.network.linux_net.QuantumLinuxBridgeInterfaceDriver")


    add_to_conf(nova_compute_conf, "DEFAULT", "libvirt_type", "qemu")
    add_to_conf(nova_compute_conf, "DEFAULT", "compute_driver", "libvirt.LibvirtDriver")
    add_to_conf(nova_compute_conf, "DEFAULT", "libvirt_vif_type", "ethernet")
    add_to_conf(nova_compute_conf, "DEFAULT", "libvirt_vif_driver", "nova.virt.libvirt.vif.QuantumLinuxBridgeVIFDriver")

    execute("nova-manage db sync")

    execute("service libvirt-bin restart", True)

    execute("service nova-api restart", True)
    execute("service nova-cert restart", True)
    execute("service nova-scheduler restart", True)
    execute("service nova-conductor restart", True)
    execute("service nova-compute restart", True)
    execute("service nova-consoleauth restart", True)
    execute("service nova-novncproxy restart", True)


def install_and_configure_quantum():
    quantum_conf = "/etc/quantum/quantum.conf"
    quantum_paste_conf = "/etc/quantum/api-paste.ini"
    quantum_plugin_conf = "/etc/quantum/plugins/linuxbridge/linuxbridge_conf.ini"
    quantum_dhcp_conf = "/etc/quantum/dhcp_agent.ini"

    execute_db_commnads("DROP DATABASE IF EXISTS quantum;")
    execute_db_commnads("CREATE DATABASE quantum;")
    execute_db_commnads("GRANT ALL PRIVILEGES ON quantum.* TO 'quantum'@'%' IDENTIFIED BY 'quantum';")
    execute_db_commnads("GRANT ALL PRIVILEGES ON quantum.* TO 'quantum'@'localhost' IDENTIFIED BY 'quantum';")

    execute("apt-get install quantum-server quantum-plugin-linuxbridge quantum-plugin-linuxbridge-agent quantum-dhcp-agent -y", True)

    add_to_conf(quantum_conf, "DEFAULT", "core_plugin", "quantum.plugins.linuxbridge.lb_quantum_plugin.LinuxBridgePluginV2")
    add_to_conf(quantum_conf, "DEFAULT", "verbose", "true")
    add_to_conf(quantum_conf, "DEFAULT", "debug", "true")
    add_to_conf(quantum_conf, "DEFAULT", "auth_strategy", "keystone")
    add_to_conf(quantum_conf, "DEFAULT", "rabbit_host", "127.0.0.1")
    add_to_conf(quantum_conf, "DEFAULT", "rabbit_port", "5672")
    add_to_conf(quantum_conf, "DEFAULT", "allow_overlapping_ips", "False")
    add_to_conf(quantum_conf, "DEFAULT", "root_helper", "sudo quantum-rootwrap /etc/quantum/rootwrap.conf")

    add_to_conf(quantum_paste_conf, "filter:authtoken", "auth_host", "127.0.0.1")
    add_to_conf(quantum_paste_conf, "filter:authtoken", "auth_port", "35357")
    add_to_conf(quantum_paste_conf, "filter:authtoken", "auth_protocol", "http")
    add_to_conf(quantum_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
    add_to_conf(quantum_paste_conf, "filter:authtoken", "admin_user", "quantum")
    add_to_conf(quantum_paste_conf, "filter:authtoken", "admin_password", "quantum")

    add_to_conf(quantum_plugin_conf, "DATABASE", "sql_connection", "mysql://quantum:quantum@localhost/quantum")
    add_to_conf(quantum_plugin_conf, "LINUX_BRIDGE", "physical_interface_mappings", "physnet1:eth1")
    add_to_conf(quantum_plugin_conf, "VLANS", "tenant_network_type", "vlan")
    add_to_conf(quantum_plugin_conf, "VLANS", "network_vlan_ranges", "physnet1:1000:2999")

    add_to_conf(quantum_dhcp_conf, "DEFAULT", "interface_driver", "quantum.agent.linux.interface.BridgeInterfaceDriver")
    add_to_conf(quantum_dhcp_conf, "DEFAULT", "use_namespaces", "False")
    add_to_conf(quantum_dhcp_conf, "DEFAULT", "verbose", "true")
    add_to_conf(quantum_dhcp_conf, "DEFAULT", "debug", "true")

    delete_file("/etc/quantum/plugin.ini")
    execute("ln -s /etc/quantum/plugins/linuxbridge/linuxbridge_conf.ini /etc/quantum/plugin.ini")
    execute("sed -i 's/\/etc\/quantum\/plugins\/openvswitch\/ovs_quantum_plugin.ini/\/etc\/quantum\/plugins\/linuxbridge\/linuxbridge_conf.ini/g' /etc/default/quantum-server")

    kill_process("dnsmasq")

    execute("service quantum-server restart", True)
    execute("service quantum-plugin-linuxbridge-agent restart", True)
    execute("service quantum-dhcp-agent restart", True)



def install_and_configure_dashboard():
    execute("apt-get install openstack-dashboard -y", True)
    execute("service apache2 restart", True)

initialize_system()
install_rabbitmq()
install_database()
install_and_configure_keystone()
install_and_configure_glance()
install_and_configure_nova()
install_and_configure_quantum()
install_and_configure_dashboard()
print_format(" Installation successfull! Login into horizon http://%s/horizon  Username:admin  Password:secret " % ip_address)
