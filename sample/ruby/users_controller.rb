require "digest"
require "net/http"

API_SECRET = "Sup3rS3cretPass!"   # hardcoded secret

class UsersController < ApplicationController
  def run(sql)
    ActiveRecord::Base.connection.execute(sql)    # parameter reaches sink
  end

  def where_name(n)
    "WHERE name = '#{n}'"
  end

  def show
    id = params[:id]
    ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = #{id}")      # VULN sql-injection
    User.where("name = '#{params[:name]}'")                                            # VULN sql-injection
    run("SELECT * FROM users " + where_name(params[:q]))                               # VULN sql-injection (cross-method)
    User.where("id = ?", params[:id])                                                  # SAFE (bind)
    User.where("id = #{params[:n].to_i}")                                              # SAFE (to_i)

    raw(params[:bio])                                                                  # VULN xss
    render html: params[:x]                                                            # VULN xss
    render plain: params[:x]                                                           # SAFE (text/plain)
    banner = params[:q].html_safe                                                      # VULN xss (html_safe)

    system("ping -c 1 #{params[:host]}")                                               # VULN command-injection
    `nslookup #{params[:host]}`                                                        # VULN command-injection
    system("ping", "-c", "1", params[:host])                                           # SAFE (argv form)

    File.read(params[:f])                                                              # VULN path-traversal
    send_file params[:path]                                                            # VULN path-traversal
    redirect_to params[:next]                                                          # VULN open-redirect
    eval(params[:expr])                                                                # VULN code-injection
    params[:klass].constantize                                                         # VULN code-injection
    Marshal.load(Base64.decode64(params[:data]))                                       # VULN insecure-deserialization
    YAML.load(params[:y])                                                              # VULN insecure-deserialization
    Net::HTTP.get(URI(params[:url]))                                                   # VULN ssrf
    ERB.new(params[:t]).result                                                         # VULN ssti
    Nokogiri::XML(params[:xml])                                                        # VULN xxe
    doc.xpath("//u[@n='#{params[:n]}']")                                               # VULN xpath-injection
    Rails.logger.info("user #{params[:u]}")                                            # VULN log-injection
    response.headers["X-Name"] = params[:n]                                            # VULN header-injection
    Regexp.new(params[:p])                                                             # VULN regex-injection

    Digest::MD5.hexdigest("pw")                                                        # weak-hash
    OpenSSL::Cipher.new("DES-ECB")                                                     # weak-cipher
    session_token = rand(1_000_000)                                                    # insecure-random
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE                                       # tls-verification-disabled
    JWT.encode({ id: id }, "secret", "HS256")                                          # insecure-jwt
  end

  Rails.application.config.middleware.insert_before 0, Rack::Cors do
    allow { origins '*' }                                                              # cors-misconfiguration
  end
end
