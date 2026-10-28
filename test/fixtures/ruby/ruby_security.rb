# Ruby Security Test Fixtures

require 'digest'
require 'jwt'
require 'rexml/document'

def test_a01_path_traversal(user_path)
    # ruleid: ruby-path-traversal
    File.read(user_path)

    # ok: ruby-path-traversal
    File.read("safe_file.txt")
end

def test_a02_crypto_failures()
    # ruleid: ruby-weak-cryptography
    Digest::MD5.hexdigest("password")

    # ok: ruby-weak-cryptography
    Digest::SHA256.hexdigest("password")
end

def test_a03_injection(cmd, user_id)
    # ruleid: ruby-command-injection
    system(cmd)

    # ok: ruby-command-injection
    system("ls -la")

    # ruleid: ruby-sql-injection
    User.where("id = #{user_id}")

    # ok: ruby-sql-injection
    User.where("id = ?", user_id)
end

def test_a04_hardcoded_secret(payload)
    # ruleid: ruby-hardcoded-secret
    JWT.encode(payload, "super_secret_jwt_key")

    # ok: ruby-hardcoded-secret
    JWT.encode(payload, ENV['JWT_SECRET'])
end

def test_a05_misconfiguration()
    # ruleid: ruby-rails-debug-all-requests-local
    config.consider_all_requests_local = true
end

def test_a06_xxe(xml)
    # ruleid: ruby-rexml-xxe
    REXML::Document.new(xml)
end

def test_a07_insecure_cookie()
    # ruleid: ruby-insecure-cookie
    cookies[:session] = { value: "token", httponly: false }

    # ok: ruby-insecure-cookie
    cookies[:session] = { value: "token", httponly: true }
end

def test_a08_deserialization(data)
    # ruleid: ruby-unsafe-deserialization
    Marshal.load(data)

    # ok: ruby-unsafe-deserialization
    JSON.parse(data)
end

def test_a10_ssrf(user_url)
    # ruleid: ruby-ssrf-http-request
    Net::HTTP.get(user_url)

    # ok: ruby-ssrf-http-request
    Net::HTTP.get("https://api.github.com/status")
end
