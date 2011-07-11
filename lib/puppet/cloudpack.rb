require 'tempfile'
require 'rubygems'
require 'fog'
require 'puppet/network/http_pool'

module Puppet::CloudPack
  require 'puppet/cloudpack/installer'
  class << self
    def add_platform_option(action)
      action.option '--platform=' do
        required
        before_action do |action, args, options|
          supported_platforms = [ 'AWS' ]
          unless supported_platforms.include?(options[:platform])
            raise ArgumentError, "Platform must be one of the following: #{supported_platforms.join(', ')}"
          end
        end
      end
    end

    def add_create_options(action)
      add_platform_option(action)

      action.option '--image=', '-i=' do
        required
        before_action do |action, args, options|
          if Puppet::CloudPack.create_connection(options).images.get(options[:image]).nil?
            raise ArgumentError, "Unrecognized image name: #{options[:image]}"
          end
        end
      end

      action.option '--type=' do
        required
        before_action do |action, args, options|
          supported_types = ['m1.small','m1.large','m1.xlarge','t1.micro','m2.xlarge','m2.2xlarge','x2.4xlarge','c1.medium','c1.xlarge','cc1.4xlarge']
          unless supported_types.include?(options[:type])
            raise ArgumentError, "Platform must be one of the following: #{supported_types.join(', ')}"
          end
        end
      end

      action.option '--keypair=' do
        required
        before_action do |action, args, options|
          if Puppet::CloudPack.create_connection(options).key_pairs.get(options[:keypair]).nil?
            raise ArgumentError, "Unrecognized keypair name: #{options[:keypair]}"
          end
        end
      end

      action.option '--group=', '-g=', '--security-group=' do
        before_action do |action, args, options|
          options[:group] = options[:group].split(File::PATH_SEPARATOR) unless options[:group].is_a? Array

          known = Puppet::CloudPack.create_connection(options).security_groups
          unknown = options[:group].select { |g| known.get(g).nil? }
          unless unknown.empty?
            raise ArgumentError, "Unrecognized security groups: #{unknown.join(', ')}"
          end
        end
      end
    end

    def add_init_options(action)
      add_install_options(action)
      add_classify_options(action)
    end

    def add_terminate_options(action)
      add_platform_option(action)
      action.option '--force', '-f'
    end

    def add_bootstrap_options(action)
      add_create_options(action)
      add_init_options(action)
    end

    def add_install_options(action)
      action.option '--login=', '-l=', '--username=' do
        required
      end

      action.option '--keyfile=' do
        required
        before_action do |action, arguments, options|
          unless test 'f', options[:keyfile]
            raise ArgumentError, "Could not find file '#{options[:keyfile]}'"
          end
          unless test 'r', options[:keyfile]
            raise ArgumentError, "Could not read from file '#{options[:keyfile]}'"
          end
        end
      end

      action.option '--installer-payload=' do
        before_action do |action, arguments, options|
          unless test 'f', options[:installer_payload]
            raise ArgumentError, "Could not find file '#{options[:installer_payload]}'"
          end
          unless test 'r', options[:installer_payload]
            raise ArgumentError, "Could not read from file '#{options[:installer_payload]}'"
          end
        end
      end

      action.option '--installer-answers=' do
        before_action do |action, arguments, options|
          unless test 'f', options[:installer_answers]
            raise ArgumentError, "Could not find file '#{options[:installer_answers]}'"
          end
          unless test 'r', options[:installer_answers]
            raise ArgumentError, "Could not read from file '#{options[:installer_answers]}'"
          end
        end
      end

      action.option '--install-script' do
        summary 'Name of the template to use for installation'
        description <<-EOT
          Name of the template to use for installation. The current
          list of supported templates is: foss, pe
        EOT
      end

      action.option '--puppet-version' do
        summary 'version of puppet to install'
        before_action do |action, arguments, options|
          unless option[:puppet_version] =~ /\d+\.\d+\.\d+/
            raise ArgumentError, "Invaid Puppet version '#{options[:puppet_version]}'"
          end
        end
      end

      action.option '--facter-version' do
        summary 'version of facter to install'
        description <<-EOT
          The version of facter that should be installed.
          This only makes sense in open source installation
          mode.
        EOT
        before_action do |action, arguments, options|
          unless option[:facter_version] =~ /\d+\.\d+\.\d+/
            raise ArgumentError, "Invaid Facter version '#{options[:facter_version]}'"
          end
        end
      end

    end

    def add_classify_options(action)
      action.option '--node-group=', '--as=' do
        required
      end
    end



    def bootstrap(options)
      options[:_destroy_server_at_exit] = :bootstrap
      server = self.create(options)
      self.init(server, options)
      options.delete(:_destroy_server_at_exit)
      return nil
    end

    def classify(certname, options)
      puts "Using http://#{Puppet[:report_server]}:#{Puppet[:report_port]} as Dashboard."
      http = Puppet::Network::HttpPool.http_instance(Puppet[:report_server], Puppet[:report_port])

      # Workaround for the fact that Dashboard is typically insecure.
      http.use_ssl = false
      headers = { 'Content-Type' => 'application/json' }

      begin
        print 'Registering node ...'
        data = { 'node' => { 'name' => certname } }
        response = http.post('/nodes.json', data.to_pson, headers)
        if (response.code == '201')
          puts ' Done'
        else
          puts ' Failed'
          Puppet.warning "Server responded with a #{response.code} status"
        end

        print 'Classifying node ...'
        data = { 'node_name' => certname, 'group_name' => options[:node_group] }
        response = http.post("/memberships.json", data.to_pson, headers)
        if (response.code == '201')
          puts ' Done'
        else
          puts ' Failed'
          Puppet.warning "Server responded with a #{response.code} status"
        end
      rescue Errno::ECONNREFUSED
        puts ' Error'
        Puppet.err "Could not connect to host http://#{Puppet[:report_server]}:#{Puppet[:report_port]}"
        Puppet.err "Check your report_server and report_port options"
        exit(1)
      end

      return nil
    end

    def create(options)
      unless options.has_key? :_destroy_server_at_exit
        options[:_destroy_server_at_exit] = :create
      end

      print "Connecting to #{options[:platform]} ..."
      connection = create_connection(options)
      puts ' Done'
      puts "#{options[:type]}"

      # TODO: Validate that the security groups permit SSH access from here.
      # TODO: Can this throw errors?
      server     = create_server(connection.servers,
        :image_id   => options[:image],
        :key_name   => options[:keypair],
        :groups     => options[:group],
        :flavor_id  => options[:type]
      )

      Signal.trap(:EXIT) do
        if options[:_destroy_server_at_exit]
          server.destroy rescue nil
        end
      end

      create_tags(connection.tags, server)

      print 'Starting up '
      retries = 0
      begin
        server.wait_for do
          print '.'
          self.ready?
        end
        puts ' Done'
      rescue Fog::Errors::Error
        puts "Failed"
        Puppet.err "Could not connect to host"
        Puppet.err "Please check your network connection and try again"
        return nil
      end

      # TODO: Find a better way of getting the Fingerprints
      begin
        print 'Waiting for host fingerprints '
        Fog.wait_for do
          print '.'
          not server.console_output.body['output'].nil?
        end or raise Fog::Errors::Error, "Waiting for host fingerprints timed out"
        puts ' Done'

        puts *server.console_output.body['output'].grep(/^ec2:/)
      rescue Fog::Errors::Error => e
        puts "Failed"
        Puppet.warning "Could not read the host's fingerprints"
        Puppet.warning "Please verify the host's fingerprints through AWS"
      end

      if options[:_destroy_server_at_exit] == :create
        options.delete(:_destroy_server_at_exit)
      end

      return server.dns_name
    end

    def init(server, options)
      certname = install(server, options)
      options.delete(:_destroy_server_at_exit)

      puts "Puppet Enterprise is now installed on: #{server}"

      classify(certname, options)

      sign(certname, options)
    end

    def sign(certname, options)
      # HACK: This should be reconciled with the Certificate Face.
      opts = options.merge(:ca_location => :remote)

      # TODO: Wait for C.S.R.?

      print "Signing certificate ..."
      begin
        Puppet::Face[:certificate, '0.0.1'].sign(certname, opts)
        puts " Done"
      rescue Puppet::Error => e
        # TODO: Write useful next steps.
        puts " Failed"
      rescue Net::HTTPError => e
        # TODO: Write useful next steps
        puts " Failed"
      end
    end

    def install(server, options)
      login    = options[:login]
      keyfile  = options[:keyfile]
      script   = options[:install_script] || 'foss'

      if not test('f', '/usr/bin/uuidgen')
        raise "/usr/bin/uuidgen does not exist; please install uuidgen."
      elsif not test('x', '/usr/bin/uuidgen')
        raise "/usr/bin/uuidgen is not executable; please change that file's permissions."
      end
      certname = `/usr/bin/uuidgen`.downcase.chomp

      opts = {}
      opts[:key_data] = [File.read(keyfile)] if keyfile

      ssh = Fog::SSH.new(server, login, opts)
      scp = Fog::SCP.new(server, login, opts)

      print "Waiting for SSH response ..."
      retries = 0
      begin
        # TODO: Certain cases cause this to hang?
        ssh.run(['hostname'])
      rescue Net::SSH::AuthenticationFailed
        puts " Failed"
        raise "Check your authentication credentials and try again."
      rescue => e
        sleep 5
        retries += 1
        print '.'
        puts " Failed"
        raise "SSH not responding; aborting." if retries > 60
        retry
      end
      puts " Done"

      tmp_dir = ssh.run('bash -c "mktemp -d /tmp/installer_script.$(echo $RANDOM)"')[0].stdout.chomp

      if options[:installer_payload]
        print "Uploading PuppetEnterprise tarball ..."
        scp.upload(options[:installer_payload], "#{tmp_dir}/puppet.tar.gz")
        puts " Done"
      end

      if options[:installer_answers]
        print "Uploading Puppet Answer File ..."
        scp.upload(options[:installer_answers], "#{tmp_dir}/puppet.answers")
        puts " Done"
      end

      print "Installing Puppet ..."
      opts[:certname] = certname
      opts[:tmp_dir] = tmp_dir
      opts[:server] = Puppet[:server]
      opts[:environment] = Puppet[:environment] || 'production'
      install_script = Puppet::CloudPack::Installer.build_installer_template(script, opts)
      tmp_install_script = Tempfile.new('install_script').path
      File.open(tmp_install_script, 'w') do |fh|
        fh.write(install_script)
      end
      print "Uploading Puppet Install Script ..."
      #tmp_dir = ssh.run('bash -c "mktemp -dt installer_script"').stdout
      # I had a craft this command b/c I noticed that mktemp does not behave
      # consistently between mac and linux
      tmp_dir = ssh.run('bash -c "mktemp -d /tmp/installer_script.$(echo $RANDOM)"')[0].stdout.chomp

      scp.upload(tmp_install_script, "#{tmp_dir}/#{script}.sh")
      cmd = "bash -c 'chmod u+x #{tmp_dir}/#{script}.sh; #{tmp_dir}/#{script}.sh | tee #{tmp_dir}/install.log'"
      #require 'ruby-debug';debugger
      puts " Done"
      result = ssh.run(login == 'root' ? cmd : "sudo #{cmd}" )
      Puppet.debug(result[0].stdout)
      puts " Done"

      return certname
    end

    def terminate(server, options)
      print "Connecting to #{options[:platform]} ..."
      connection = create_connection(options)
      puts ' Done'

      servers = connection.servers.all('dns-name' => server)
      if servers.length == 1 || options[:force]
        servers.each { |server| server.destroy() }
      elsif servers.empty?
        Puppet.warning "Could not find server with DNS name '#{server}'"
      else
        Puppet.err "More than one server with DNS name '#{server}'; aborting"
      end

      return nil
    end


    def create_connection(options = {})
      Fog::Compute.new(:provider => options[:platform])
    end

    def create_server(servers, options = {})
      print 'Creating new instance ...'
      server = servers.create(options)
      puts ' Done'
      return server
    end

    def create_tags(tags, server)
      print 'Creating tags for instance ...'
      tags.create(
        :key         => 'Created-By',
        :value       => 'Puppet',
        :resource_id => server.id
      )
      puts ' Done'
    end
  end
end
