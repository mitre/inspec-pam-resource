# frozen_string_literal: true
 
# The `Pam::Rule` class in Ruby represents a PAM rule and provides
# methods to check its validity.
# The Pam::Rule class represents a single rule in a PAM configuration.
# Each rule has a service, type, control, module path, and optional module arguments.
#
# @attr_reader [String] service The service name of the rule
# @attr_reader [String] type The type of the rule
# @attr_reader [String] control The control of the rule
# @attr_reader [String] module_path The module path of the rule
# @attr_reader [Array<String>] module_arguments The module arguments of the rule
class Pam::Rule
  attr_reader :service, :type, :control, :module_path, :module_arguments

  # Constants for the valid types and controls a rule can have
  VALID_TYPES = ['auth', 'account', 'password', 'session'].freeze
  VALID_CONTROLS = ['required', 'requisite', 'sufficient', 'optional'].freeze

  # Initializes a new rule.
  # The rule argument should be a string containing the type, control, module path, and optional module arguments.
  # The options hash can contain a :service_name key to set the service of the rule.
  #
  # @param [String] rule The rule string
  # @param [Hash] options The options for the rule
  # @option options [String] :service_name The service name of the rule
  # @raise [ArgumentError] If the rule is not a string or does not contain at least four parts
  def initialize(rule, options = {})
    raise ArgumentError, 'rule must be a string' unless rule.is_a?(String)

    parts = rule.split(/\s+/)
    raise ArgumentError, 'rule must contain at least four parts' unless parts.size >= 4

    @service = options[:service_name]
    @type, @control, @module_path, *module_arguments = parts
    @module_arguments = module_arguments
  end

  # Checks if the rule is valid.
  # A rule is valid if its type and control are in the list of valid types and controls,
  # and if its module path is not nil.
  #
  # @return [Boolean] True if the rule is valid, false otherwise
  def valid?
    VALID_TYPES.include?(@type) && VALID_CONTROLS.include?(@control) && !@module_path.nil?
  end
end

# The Pam::Rules class represents a collection of PAM rules.
class Pam::Rules
  # Initializes a new collection of rules.
  def initialize
    @rules = []
  end

  # Adds a rule to the collection.
  # The rule argument should be an instance of Pam::Rule.
  #
  # @param [Pam::Rule] rule The rule to add
  # @raise [ArgumentError] If the rule is not an instance of Pam::Rule
  def add(rule)
    raise ArgumentError, 'rule must be an instance of Pam::Rule' unless rule.is_a?(Pam::Rule)

    @rules << rule
  end

  # Checks if the collection includes a specific rule.
  #
  # @param [Pam::Rule] rule The rule to check
  # @return [Boolean] True if the collection includes the rule, false otherwise
  # @raise [ArgumentError] If the rule is not an instance of Pam::Rule
  def include?(rule)
    raise ArgumentError, 'rule must be an instance of Pam::Rule' unless rule.is_a?(Pam::Rule)

    @rules.any? { |r| r == rule }
  end

  # Returns all rules of a specific type.
  #
  # @param [String] type The type of rules to return
  # @return [Array<Pam::Rule>] The rules of the specified type
  # @raise [ArgumentError] If the type is not a string
  def rules_of_type(type)
    raise ArgumentError, 'type must be a string' unless type.is_a?(String)

    @rules.select { |r| r.type == type }
  end
end
class PamParser
  def initialize(pam)
    raise ArgumentError, 'pam must be an instance of Pam' unless pam.is_a?(Pam)

    @pam = pam
  end

  def parse_content(path, service_name = nil)
    raise ArgumentError, 'path must respond to :directory?' unless path.respond_to?(:directory?)

    config_files = path.directory? ? Dir[path.join('*')].map { |f| inspec.file(f) } : [inspec.file(path)]

    config_files.each do |config_file|
      next unless config_file.content

      rules = config_file.content.gsub("\\\n", ' ').lines.map(&:strip).reject { |line| line =~ /^(\s*#.*|\s*)$/ }

      service = service_name || (!@pam.top_config && config_file.basename)

      rules.each do |rule|
        process_rule(rule, service, config_file)
      end
    end
  end

  def process_rule(rule, service, config_file)
    new_rule = Pam::Rule.new(rule, { service_name: service })

    if ['include', 'substack'].include?(new_rule.control)
      subtarget = new_rule.module_path.start_with?('/') ? inspec.file(new_rule.module_path) : inspec.file(@pam.path.join(new_rule.module_path))

      parse_content(subtarget, service) if subtarget.exist?
    else
      raise PamError, "Invalid PAM config found at #{config_file}" unless new_rule.valid?

      @pam.rules.add(new_rule)
      @pam.services[new_rule.service].add(new_rule)
      @pam.types[new_rule.type].add(new_rule)
      @pam.modules[new_rule.module_path].add(new_rule)
    end
  end
end
class Pam < Inspec.resource(1)
  
  attr_reader :services, :types, :modules, :rules, :path, :top_config
  
  name "pam"
  supports platform: "unix"
  desc "Use the InSpec pam resource to test the given system pam configuration"
  example "
    # Query for a match:

    describe pam('/etc/pam.d/system-auth') do
      its('rules') { should match_pam_rule('password sufficient pam_unix.so sha512') }
    end

    # Query everything for a match without specific arguments
    # You can use a Ruby regexp match for everything except arguments

    describe pam('/etc/pam.d') do
      its('rules') { should match_pam_rule('.* .* pam_unix.so').all_without_args('nullok' }
    end

    # Query for multiple lines

    describe pam('/etc/pam.d/password-auth') do
      required_rules = [
        'auth required pam_faillock.so',
        'auth sufficient pam_unix.so try_first_pass'
      ]
      its('rules') { should match_pam_rules(required_rules) }
    end

    # Query for multiple rules without any rules in between them

    describe pam('/etc/pam.d/password-auth') do
      required_rules = [
        'auth required pam_faillock.so',
        'auth sufficient pam_unix.so try_first_pass'
      ]
      its('rules') { should match_pam_rules(required_rules).exactly }
    end
  "

  class PamError < StandardError; end

  def initialize(path = '/etc/pam.d')
    @path = Pathname.new(path)
    @services, @types, @modules = Hash.new { |h, k| h[k] = Pam::Rules.new }, Hash.new { |h, k| h[k] = Pam::Rules.new }, Hash.new { |h, k| h[k] = Pam::Rules.new }
    @rules = Pam::Rules.new

    @top_config = @path.to_s.strip == '/etc/pam.conf'

    PamParser.new(self).parse_content(@path)
  end

  # Process a PAM configuration file
  #
  # @param [String] path The path to the file or directory to process
  # @param [String] service_name The PAM Service under which the content falls.
  #   Mainly used for recursive processing
  def parse_content(path, service_name = nil)
    config_files = path.directory? ? Dir[path.join("*")].map { |f| inspec.file(f) } : [inspec.file(path)]

    config_files.each do |config_file|
      next unless config_file.content

      rules = config_file.content.gsub("\\\n", " ").lines.map(&:strip).reject { |line| line =~ /^(\s*#.*|\s*)$/ }

      service = service_name || (!@top_config && config_file.basename)

      rules.each do |rule|
        process_rule(rule, service, config_file)
      end
    end
  end

  def process_rule(rule, service, config_file)
    new_rule = Pam::Rule.new(rule, { service_name: service })

    if ["include", "substack"].include?(new_rule.control)
      subtarget = new_rule.module_path.start_with?("/") ? inspec.file(new_rule.module_path) : inspec.file(@path.join(new_rule.module_path))

      parse_content(subtarget, service) if subtarget.exist?
    else
      raise PamError, "Invalid PAM config found at #{config_file}" unless new_rule.valid?

      @services[new_rule.service] << new_rule
      @types[new_rule.type] << new_rule
      @modules[new_rule.module_path] << new_rule

      @rules.push(new_rule)
    end
  end

  def to_s
    "PAM Config[#{@path}]"
  end

  def service(service_name)
    @services[service_name]
  end

  def type(type_name)
    @types[type_name]
  end

  def module(module_name)
    @modules[module_name]
  end

  # The list of rules with a bunch of helpers for matching in the future
  #
  # We do fuzzy matching across the board when checking for internal rule
  # matches
  class Rules < Array
    def initialize(config_target)
      @config_target = config_target
    end

    def services
      collect(&:service).sort.uniq
    end

    def service
      svcs = collect(&:service).sort.uniq
      raise PamError, %(More than one service found: '[#{svcs.join("', '")}]') if svcs.length > 1

      svcs.first
    end

    def first?(rule, opts = { service_name: nil })
      raise PamError, "opts must be a hash" unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      rule = Pam::Rule.new(rule, { service_name: service_name })

      rules_of_type(rule.type, opts).first == rule
    end

    def last?(rule, opts = { service_name: nil })
      raise PamError, "opts must be a hash" unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      _rule = Pam::Rule.new(rule, { service_name: service_name })

      rules_of_type(_rule.type, opts).last == _rule
    end

    def rules_of_type(rule_type, opts = { service_name: nil })
      raise PamError, "opts must be a hash" unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      if @services[service_name]
        @services[service_name].find_all do |l|
          l.type == rule_type
        end
      else
        []
      end
    end

    # Determines if one or more rules are contained in the rule set
    #
    # @param [Array[String] rules The Rules to find
    # @param [Hash] opts Options for the include processor
    # @option opts [Boolean] :exact
    #   If set, no rules may be present between the rules provided in `rules`
    #   If unset, the rules simply need to be in the correct order, other rules
    #   may appear between them
    # @option opts [String] :service_name The PAM Service under which the rules
    #   should be searched
    # @return [Boolean] true if found, false otherwise
    def include?(rules, opts = { exact: false, service_name: nil })
      raise PamError, "opts must be a hash" unless opts.is_a?(Hash)

      service_name = get_service_name(opts[:service_name])

      rules = Array(rules).map { |l| Pam::Rule.new(l, { service_name: service_name }) }

      retval = false

      if opts[:exact]
        # This requires everything between the first and last rule to match
        # exactly

        first_entry = index(rules.first)
        last_entry = index(rules.last)

        retval = (self[first_entry..last_entry] == rules) if first_entry && last_entry
      else
        # This match allows other rules between the two in question
        retval = (rules.select { |l| super(l) } == rules)
      end

      retval
    end

    alias match include?

    # An alias for setting `:exact => true` in the `include` method
    def include_exactly?(rules, opts = {})
      include?(rules, opts.merge({ exact: true }))
    end

    alias match_exactly include_exactly?

    # Convert the data structure to an Array suitable for an RSpec diff
    #
    # @return [Array[String]]
    def to_a
      sort_by(&:type).map(&:to_s)
    end

    # Convert the data structure to a String
    #
    # @return [String]
    def to_s
      to_a.join("\n")
    end

    private

    # Get the service name out of the configuration target
    #
    # @param [String] svc_name Optional name of the service that should be
    #    returned
    #
    # @return String
    def get_service_name(svc_name = nil)
      return svc_name if svc_name

      if !svc_name && @config_target.directory?
        raise PamError, 'You must pass ":service_name" as an option!'
      else
        @config_target.basename
      end
    end
  end

  # A single Rule object that has been processed
  #
  # Rule equality is a fuzzy match that can accept regular expression matches
  # within the string to compare
  class Rule
    attr_reader :to_s, :service, :silent, :type, :control, :module_path, :module_arguments

    def initialize(rule, opts = {})
      @to_s = rule.strip.gsub(/\s+/, " ")

      rule_regex = <<-'EOM'
        # Start of Rule
          ^
        # Ignore initial Whitespace
          \s*
        # Capture Silent Flag
          (?<silent>-)?
      EOM

      unless opts[:service_name]
        rule_regex += <<-'EOM'
          # Capture Service
            (?<service_name>.+?)\s+
        EOM
      end

      rule_regex += <<-'EOM'
        # Capture Type
          (?<type>.+?)\s+
        # Capture Control
          (?<control>(\[.+\]|.+?))\s+
        # Capture Module Path
          (?<module_path>.+?(\.so)?)
        # Capture Module Args
          (\s+(?<module_args>.+?))?
        # End of Rule
          $
      EOM

      match_data = rule.match(Regexp.new(rule_regex, Regexp::EXTENDED))

      raise PamError, "Invalid PAM configuration rule: '#{rule}'" unless match_data

      @service = opts[:service_name] || match_data[:service_name]
      @silent = match_data[:silent] == "-"
      @type = match_data[:type]
      @control = match_data[:control]
      @module_path = match_data[:module_path]
      @module_arguments = match_data[:module_args] ? match_data[:module_args].strip.split(/\s+/) : []
    end

    def match?(to_cmp)
      to_cmp = Pam::Rule.new(to_cmp, { service_name: @service }) if to_cmp.is_a?(String)

      # The simple match first
      instance_of?(to_cmp.class) &&
        @service.match(Regexp.new("^#{to_cmp.service}$")) &&
        @type.match(Regexp.new("^#{to_cmp.type}$")) &&
        @control.match(Regexp.new("^#{to_cmp.control.gsub(/(\[|\])/, '\\\\\\1')}$")) &&
        @module_path.match(Regexp.new("^#{to_cmp.module_path}$")) &&
        (
 # Quick test to pass if to_cmp module_arguments are a subset
          (to_cmp.module_arguments - @module_arguments).empty? ||
          # All module_arguments in to_cmp should Regex match something
          to_cmp.module_arguments.all? do |arg|
            !@module_arguments.grep(Regexp.new("^#{arg}$")).empty?
          end)
    end

    alias == match?
    alias eql? ==
  end
end
