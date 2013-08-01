#!/usr/bin/ruby
#
#
require 'digest'
require 'fileutils'
require 'getoptlong'
require 'zlib'

class Sautobuild

  attr_reader :build_dir, :source_dir, :sources_list, :apt_conf
  attr_writer :source, :update_chroot

  def initialize(dir)
    raise Errno::ENOENT, dir unless File.exists?(dir)
    raise Errno::ENOTDIR, dir unless File.directory?(dir)

    @source_dir = File.expand_path(dir)
    @build_dir = File.expand_path(File.join(@source_dir, ".."))
    @update_chroot = false
    @version, @source, @distribution, @architecture = nil
    @architectures = @available_architectures = @available_distributions = []
    @sources_list = @apt_conf = nil
  end

  def changelog; File.join(@source_dir, "debian", "changelog"); end

  def distribution
    do_read_changelog if @distribution.nil?
    @distribution
  end

  def distribution=(d)
    raise ArgumentError, "Unknown distribution #{d}" unless self.available_distributions.include?(d)
    @distribution = d
  end

  def source
    do_read_changelog if @source.nil?
    @source
  end

  def version
    do_read_changelog if @version.nil?
    @version
  end

  def version=(v)
    @version = v.gsub(/^[0-9]*:/,'')
  end

  def architecture
    do_read_dsc if @architecture.nil?
    @architecture
  end
  
  def architecture=(a); @architecture = a; end

  def architectures
    do_read_dsc if @architecture.nil?
    return [] if @architecture.nil?

    self.architectures = @architecture.split(" ") if @architectures.empty?
    @architectures
  end

  def architectures=(archs)
    archs.each do |a|
      if self.available_architectures.include?(a) or %w(all any).include?(a)
        @architectures << a
      else
        warn "Unknown architecture #{a}"
      end
    end

    raise ArgumentError, "No valid/available architectures found in #{as.inspect}"

    @architectures
  end

  def sources_list=(f)
    f = File.expand_path(f)
    raise Errno::ENOENT, f unless File.exists?(f)
    @update_chroot = false
    @sources_list = f
  end

  def apt_conf=(f)
    f = File.expand_path(f)
    raise Errno::ENOENT, f unless File.exists?(f)
    @update_chroot = false
    @apt_conf = f
  end

  def dsc; File.join(@build_dir,source+"_"+version+".dsc") ; end

  def build_architectures
    build_archs = []

    self.architectures.each do |a|
      case a
      when "any"
        build_archs += self.available_architectures
      when "all"
        build_archs << `dpkg-architecture -qDEB_BUILD_ARCH_CPU`.chomp
      else
        build_archs << a if self.available_architectures.include?(a)
      end
    end

    build_archs.sort.uniq
  end

  def available_distributions
    do_find_distributions_and_architectures if @available_distributions.empty?
    @available_distributions
  end

  def available_architectures
    do_find_distributions_and_architectures if @available_architectures.empty?
    @available_architectures 
  end

  def build
    do_build_source
    do_build_debs
  end

  def check(exit_if_fail = false)
    changes = (%w(source)+build_architectures).collect do |arch|
      File.join(@build_dir,@source+"_"+@version+"_"+arch+".changes")
    end

    if !system("schroot -c #{self.distribution} -- lintian -X cpy -I #{changes.join(" ")}") and exit_if_fail
      exit $?.exitstatus
    end
  end

  def make_repo(args={})
    args[:hashes] = do_make_sources_and_packages_files()
    do_make_releases_file(args)
  end

  private

  def do_or_die(c); puts "="*80+"\n"+c ; exit $?.exitstatus unless system(c); end
  
  def do_read_fields_from_io(io)
    raise ArgumentError, "Not an IO object" unless io.is_a?(IO)

    while (l = io.gets) do
      next unless l.chomp =~ /([^:]+): (.+)/
      field = $1.downcase
      value = $2
      #
      # Deal with 1.8 and 1.9 instance variables
      #
      ivar = "@#{field}"
      ivar = ivar.to_sym unless /^1\.8/ =~ RUBY_VERSION

      next unless self.instance_variables.include?(ivar) and self.instance_variable_get(ivar).nil?
      next unless self.respond_to?(field+"=")
      self.__send__(field+"=",value)
    end
  end

  def do_read_changelog
    raise Errno::ENOENT, self.changelog unless File.file?(self.changelog)

    IO.popen("dpkg-parsechangelog -l#{self.changelog}") do |io| 
      do_read_fields_from_io(io)
    end
  end

  def do_read_dsc
    raise Errno::ENOENT, self.dsc unless File.file?(self.dsc)

    File.open(self.dsc) do |fh|
      do_read_fields_from_io(fh)
    end
  end

  def do_find_distributions_and_architectures
    valid_architectures = []
    IO.popen("dpkg-architecture -L") do |io|
      valid_architectures = io.readlines.collect{|l| l.chomp}
    end

    archs = []
    dists = []

    IO.popen("schroot -l") do |io|
     io.readlines.each do |l|
        next unless l =~ /^(?:(?:chroot|source):)?([^-]+)-(.*)$/
        dist, arch = [$1, $2]
        next unless valid_architectures.include?(arch)
        dists << dist unless dists.include?(dist)
        archs << arch unless archs.include?(arch)
      end
    end
    @available_distributions = dists unless dists.empty?
    @available_architectures = archs unless archs.empty?
  end

  def do_build_source
    puts "Building source package in #{@source_dir}"
    do_or_die("cd #{@build_dir}  && dpkg-source -I -b #{@source_dir}")
    do_or_die("cd #{@source_dir} && dpkg-genchanges -S > #{@build_dir}/#{source}_#{version}_source.changes")
  end

  def do_build_debs
    # 
    # Only need to build all arches once.
    #
    built_all = false 

    self.build_architectures.each do |arch|
      cmd = ["cd #{@build_dir} && sbuild --arch=#{arch} --verbose --dist=#{self.distribution}"]
      if !built_all
        cmd << "--arch-all" 
        built_all = true
      end


      if self.apt_conf or self.sources_list
        cmd << "--no-apt-update"
        cmd << "--no-apt-upgrade" if @update_chroot

        if self.apt_conf
          cmd << "--chroot-setup-commands='sudo cp #{self.apt_conf} /etc/apt/apt.conf.d/'"
        end

        if self.sources_list
          cmd << "--chroot-setup-commands='sudo cp #{self.sources_list} /etc/apt/sources.list.d/'" 
        end

        cmd << "--chroot-setup-commands='sudo apt-get update'"
        cmd << "--chroot-setup-commands='sudo apt-get upgrade'" if @update_chroot
      elsif @update_chroot
        cmd << "--apt-upgrade"
      end

      cmd << self.dsc
      do_or_die(cmd.join(" "))
    end
  end

  def do_make_sources_and_packages_files
    do_or_die("cd #{@build_dir} && dpkg-scansources . /dev/null > Sources.new")
    do_or_die("cd #{@build_dir} && dpkg-scanpackages -m . /dev/null > Packages.new")

    hashes = Hash.new{|h,k| h[k] = Array.new}

    %w(Sources Packages).each do |f|
      target = File.join(@build_dir,f)
      FileUtils.mv("#{target}.new", target, :force => true)
      Zlib::GzipWriter.open("#{target}.gz") do |gz|
        gz.write File.read(target)
      end

      #
      # Generate the hashes
      [Digest::MD5, Digest::SHA1, Digest::SHA256].each do |hash|
        ["",".gz"].each do |e|
          hashes[hash.to_s.split(":").last] << ["",hash.hexdigest(File.read(target+e)), File.stat(target+e).size, File.basename(target+e)]
        end
      end
    end

    return hashes
  end

  def do_make_releases_file(args)
    #
    # Now write the release file
    #
    release =<<EOF
Archive: #{self.distribution}
Label: #{args[:label] || "Unknown"}
Origin: #{args[:origin] || "Unknown"}
Architectures: #{self.build_architectures} source
Components: #{args[:components] || "main"}
EOF
    #
    # Add the hashes.
    #
    release << "MD5Sum: \n"+args[:hashes]["MD5"].collect{|m| m.join(" ")}.join("\n")+"\n"
    release << "SHA1: \n" + args[:hashes]["SHA1"].collect{|m| m.join(" ")}.join("\n")+"\n"
    release << "SHA256: \n" + args[:hashes]["SHA256"].collect{|m| m.join(" ")}.join("\n")+"\n"
    
    #
    # And write.
    target = File.join(@build_dir,"Release")
    File.open(target+".new","w+"){|fh| fh.puts(release)}
    FileUtils.mv("#{target}.new", target, :force => true)
  end

end

