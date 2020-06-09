# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  config.vbguest.auto_update = false

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "4096"
  end

  config.vm.provision "shell", inline: <<-SHELL
    echo "sudo su -" >> .bashrc
  SHELL

  ## Install golang
  config.vm.provision "shell", inline: <<-SHELL
    curl -sLO https://dl.google.com/go/go1.14.3.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.14.3.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/golang.sh
  SHELL

  ## Install bcc
  config.vm.provision "shell", inline: <<-SHELL
    apt-get -yqq update && apt-get install -yqq linux-headers-$(uname -r) bison build-essential cmake flex g++ git libelf-dev zlib1g-dev libfl-dev systemtap-sdt-dev binutils-dev llvm-8-dev llvm-8-runtime libclang-8-dev clang-8 arping netperf iperf3 python3-distutils
    git clone --recurse-submodules https://github.com/iovisor/bcc.git
    mkdir bcc/build; cd bcc/build
    cmake -DPYTHON_CMD=python3 ..
    make -j8 && make install && ldconfig
  SHELL
end