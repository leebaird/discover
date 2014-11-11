#!/usr/bin/env ruby
# Copyright (C) 2013 www.pentestgeek.com Royce Davis (@r3dy__)
#
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as 
# published by the Free Software Foundation, either version 3 of the License, or any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>

begin
  require 'nokogiri'
  require 'csv'
  require 'optparse'
rescue LoadError
    puts 'Missing gems. Make sure to install: csv, nokogiri using \'gem install <gem>\''
    exit
end

# This is the main parsing method which will run on each finding in 'issue' (or finding) in the Burp XML file.
def clean_finding(finding)
  output = []
  output << ''
  output << finding.css('severity').text               # Severity
  output << ''
  output << finding.css('host').text                   # URL
  output << finding.css('path').text                   # Path
  output << finding.css('name').text                   # Vulnerability
  output << finding.css('issueBackground').text        # Description
  output << finding.css('issueDetail').text            # Proof
  output << finding.css('remediationBackground').text  # Solution
  response = finding.css('response').text
  output
end

options = {}

optparse = OptionParser.new do|opts|
    opts.banner = "Parse Burp Suite XML output into CSV results.\r\nUsage: #{$0} [options]"

    opts.on('-i', '--infile FILE', 'Input XML file') do |file|
      raise 'No such file' unless File.exists?(file)
      options[:infile] = file
    end

    opts.on('-o', '--outfile FILE', 'Output CSV file') do |file|
      options[:outfile] = file
    end

    options[:help] = opts.help
end

# Parse the arguments to the script
optparse.parse!
begin
  raise OptionParser::MissingArgument if options[:infile].nil?
  raise OptionParser::MissingArgument if options[:outfile].nil?
rescue OptionParser::MissingArgument
  puts options[:help]
  exit
end

# Create an XML object from the file provided at runtime
report = Nokogiri::XML(File.open(options[:infile]))

# This is just a string that serves as the title line of the CSV output
CSV.open(options[:outfile], 'w') do |csv|
  csv << [
    'Phase', 
    'Severity',
    'Validation',
    'URL',
    'Path',
    'Vulnerability',
    'Description',
    'Proof',
    'Solution']

    report.xpath('//issues/issue').each do |finding|
        csv << clean_finding(finding)
    end
end

