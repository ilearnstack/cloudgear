CloudGear
=========

Here we are going to deploy openstack on a single node, i.e all openstack components Nova, Glance, Keystone, Quantum and Horizon will be running in the same box. Nova-compute is also running on the same machine which will provision virtual machines on the KVM.

Requirements:

* Ubuntu 12.04 running on Oracle VirtualBox with two NIC ‘s.

* Setup a ubuntu virtual machine in virtualBox. (can follow Guide http://ilearnstack.wordpress.com/2013/04/13/setting-ubuntu-vm-in-virtualbox/)

* Add a second NIC to the VM.

* Power Off the Virtual Machine

* In the Network Section select Adapter 2 tab

* Select “Attached to:” to internal

* Power On the VM

* When the VM boots up configure to network for second NIC
  Edit /etc/network/interfaces to something like

* Restart Network service
  service networking restart

* You can verify your network setting using “ ifconfig ”

Deploying Openstack
====================

* Login to the ubuntu VM.
* Change the user to root.
  sudo -i

* If your network is behind proxy then please export proxy variables.
   export http_proxy=<proxy-server>
   export https_proxy=<proxy-server>
   export no_proxy=”localhost,127.0.0.1″

* Install git on the machine
   apt-get install git -y

* Clone the CloudGear git to install Openstack
   git clone https://github.com/ilearnstack/cloudgear.git

* Execute the script to set up openstack
   cd cloudgear/
   python cloudgear.py

* Open Openstack Dashboard in browser from URL  http://<controller-ip>/horizon

* Login with credentials  admin/secret
