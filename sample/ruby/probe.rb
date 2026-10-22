class ProbeController < ApplicationController
  def probe_rb
    Digest::MD5.hexdigest(pw)                                      # VULN weak-hash
    Digest::SHA256.hexdigest(pw)                                   # SAFE
    OpenSSL::Cipher.new("des-cbc")                                 # VULN weak-cipher
    token = rand(100000).to_s                                      # VULN insecure-random
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE                   # VULN tls-verification-disabled
    Regexp.new(params[:p])                                         # VULN regex-injection
    Regexp.new(Regexp.escape(params[:p]))                          # SAFE
    logger.info("login #{params[:user]}")                          # VULN log-injection
    response.headers["X-A"] = params[:a]                           # VULN header-injection
    Nokogiri::XML(params[:x]) { |c| c.noent }                      # VULN xxe
    Marshal.load(params[:d])                                       # VULN insecure-deserialization
    YAML.load(params[:y])                                          # VULN insecure-deserialization
    doc.xpath("//u[@n='#{params[:n]}']")                           # VULN xpath-injection
    ERB.new(params[:t]).result                                     # VULN ssti
    response.headers["Access-Control-Allow-Origin"] = "*"          # VULN cors-misconfiguration
    api_key = "sk_live_abcdefghijklmnop1234"                       # VULN hardcoded-secret
  end
end

class ProbeMoreController < ApplicationController
  config.consider_all_requests_local = true                        # VULN debug-enabled
  def probe_rb_more
    params[:k].constantize                                         # VULN unsafe-reflection
    obj.send(params[:m])                                           # VULN unsafe-reflection
    obj.send(:fixed)                                               # SAFE
    cookies[:sid] = { value: v, secure: false, httponly: true }    # VULN insecure-cookie
    cookies[:sid] = { value: v, secure: true, httponly: true }     # SAFE
    User.create(params[:user])                                     # VULN mass-assignment
    User.create(params.require(:user).permit(:name))               # SAFE
    User.where(name: params[:name])                                # SAFE
  end
end
