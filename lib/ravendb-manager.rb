require 'net/http'
require 'digest/sha1'
require 'base64'
require 'securerandom'
require 'json'

class RavenDBManager
	@hostname
	@port
	@api_key_name
	@api_key_secret
	@bearer_token
	
	@uri
	@oauth_endpoint

	def self.create(server_url, api_key)
		uri = URI.parse(server_url)
		api_key_parts = api_key.split('/')

		return RavenDBManager.new(uri.host, uri.port, api_key_parts[0], api_key_parts[1])
	end

	def initialize(hostname, port, api_key_name, api_key_secret)
		raise 'hostname is empty' unless !hostname.to_s.empty?
		raise 'port is invalid' unless port.to_i != 0
		raise 'api_key_name empty' unless !api_key_name.to_s.empty?
		raise 'api_key_secret empty' unless !api_key_secret.to_s.empty?

		@hostname = hostname.to_s
		@port = port.to_i
		@api_key_name = api_key_name.to_s
		@api_key_secret = api_key_secret.to_s
		
		@uri = "http://#{@hostname}:#{port}"
		@oauth_endpoint = URI.parse("#{@uri}/OAuth/API-Key")
		
		@bearer_token = get_bearer_token
	end

	def bearer_token
		@bearer_token
	end

	def list_databases
		start = 0
		databases = []

		results = []
		loop do
			response = http_get("/databases/?pageSize=1024&start=#{start}")
			raise get_error_string(response) unless is_success?(response)
			results = JSON.parse(response.body)
			databases = databases + results
			start += 1024
			break if results.length < 1024
		end

		return databases
	end

	def list_filesystems
		start = 0
		filesystems = []

		results = []
		loop do
			response = http_get("/fs/?pageSize=1024&start=#{start}")
			raise get_error_string(response) unless is_success?(response)
			results = JSON.parse(response.body)
			filesystems = filesystems + results
			start += 1024
			break if results.length < 1024
		end

		return filesystems
	end

	def version
		response = http_get('/databases/<system>/build/version')
		raise get_error_string(response) unless is_success?(response)
		return JSON.parse(response.body)
	end

	def alerts(database = '<system>')
		raise "Invalid database name #{database}" unless is_valid_string?(database)

		doc = get_document(database, 'Raven/Alerts')
		return doc.nil? ? [] : doc['Alerts']
	end

	def create_database(name, useVoron = false)
		raise "Invalid database name #{name}" unless is_valid_string?(name)
		raise "Invalid parameter useVoron" unless !!useVoron == useVoron

		db_document = { 
			'Id' => name, 
			'Settings' => {
				'Raven/ActiveBundles' => "", 
				'Raven/DataDir' => "~/#{name}",
				'Raven/StorageTypeName' => useVoron ? 'voron' : 'esent'
			}, 
			'SecuredSettings'=> {}, 
			'Disabled' => false}
			.to_json

		response = http_put("/admin/databases/#{name}", db_document)
		raise get_error_string(response) unless is_success?(response)
		return nil
	end

	def create_filesystem(name)
		raise "Invalid filesystem name #{name}" unless is_valid_string?(name)

		fs_document = { 
			'Id' => name, 
			'Settings' => {
				'Raven/ActiveBundles' => "", 
				'Raven/FileSystem/DataDir' => "~/#{name}"
			}, 
			'SecuredSettings'=> {}, 
			'Disabled' => false}
			.to_json

		response = http_put("/admin/fs/#{name}", fs_document)
		raise get_error_string(response) unless is_success?(response)
		return nil
	end

	def get_document(database, key)
		raise "Invalid database name #{database}" unless is_valid_string?(database)
		raise "Invalid key #{key}" unless key.to_s.length > 0

		response = http_get("/databases/#{database}/docs?id=#{key}")
		if is_success?(response)
			return JSON.parse(response.body)
		elsif response.code == '404'
			return nil
		else
			raise get_error_string(response)
		end
	end

	def put_document(database, key, document)
		raise "Invalid database name #{database}" unless is_valid_string?(database)
		raise "Invalid key #{key}" unless key.to_s.length > 0
		raise "Invalid document" if document.nil?

		response = http_put("/databases/#{database}/docs/#{key}", document.to_json)
		raise get_error_string(response) unless is_success?(response)
		return JSON.parse(response.body)['Key']
	end

	def delete_document(database, key)
		raise "Invalid database name #{database}" unless is_valid_string?(database)
		raise "Invalid key #{key}" unless key.to_s.length > 0

		response = http_delete("/databases/#{database}/docs/#{key}")
		raise get_error_string(response) unless is_success?(response)
		return nil
	end

	def get_indexing_status(database)
		raise "Invalid database name #{database}" unless is_valid_string?(database)

		response = http_get("/databases/#{database}/admin/IndexingStatus")
		raise get_error_string(response) unless is_success?(response)
		return JSON.parse(response.body)['IndexingStatus']
	end

	def compact_database(database)
		raise "Invalid database name #{database}" unless is_valid_string?(database)

		response = http_post("/admin/compact?database=#{database}")
		raise get_error_string(response) unless is_success?(response)
		return JSON.parse(response.body)['OperationId']
	end

	def get_operation_status(operation_id)
		raise "Invalid OperationId #{operation_id}" if operation_id.nil?

		response = http_get("/operation/status?id=#{operation_id}")
		return is_success?(response) ? JSON.parse(response.body) : nil
	end

	def database_statistics(database)
		raise "Invalid database name #{database}" unless is_valid_string?(database)

		response = http_get("/databases/#{database}/stats")
		raise get_error_string(response) unless is_success?(response)
		return JSON.parse(response.body)
	end

	def server_statistics
		response = http_get("/admin/stats")
		raise get_error_string(response) unless is_success?(response)
		return JSON.parse(response.body)
	end

	# Backup ...

	def create_api_key(name)
		raise "Invalid ApiKey name #{name}" unless is_valid_string?(name)

		document = {
			'Enabled' => true,
			'Name' => name,
			'Secret' => generate_secret,
			'Databases': []
		}
		key = "Raven/ApiKeys/#{name}"
		put_document('<system>', key, document)
		return "#{name}/#{document['Secret']}"
	end

	def add_db_to_api_key(api_key_name, db_name, admin = false, readonly = false)
		raise "Invalid ApiKey name #{api_key_name}" unless is_valid_string?(api_key_name)
		raise "Invalid database name #{db_name}" unless is_valid_string?(db_name)
		raise "Invalid parameter admin" unless !!admin == admin
		raise "Invalid parameter readonly" unless !!readonly == readonly

		key = "Raven/ApiKeys/#{api_key_name}"
		document = get_document('<system>', key)
		raise "API-Key #{api_key_name} doesn't exist" if document.nil?
		document['Databases'] = document['Databases'].select {|db| db['TenantId'] != db_name}
		document['Databases'].push({'TenantId' => db_name, 'admin' => admin, 'readonly' => readonly})
		put_document('<system>', key, document)
		return nil
	end

	private

	PASSWORD_CHARS = [*('a'..'z'),*('A'..'Z'),*(0..9)]
	NAME_PATTERN = /^[a-zA-Z0-9.-<>]+$/

	def generate_secret
		return (16 + SecureRandom.random_number(4)).times.map { PASSWORD_CHARS[SecureRandom.random_number(PASSWORD_CHARS.length)] }.join
	end

	def is_valid_string?(str)
		return !NAME_PATTERN.match(str).nil?
	end

	def is_success?(http_response)
		code = http_response.code.to_i
		return code >= 200 && code <= 299
	end

	def get_error_string(http_error_response) 
		if http_error_response.methods.include?(:body) and !http_error_response.body.to_s.empty?
			return http_error_response.body
		else
			return "#{http_error_response.code} #{http_error_response.message}"
		end
	end

	def http_get(url, is_retry=false)
		http = Net::HTTP.new(@hostname, @port)
		request = Net::HTTP::Get.new(URI.escape(url))
		request['Authorization'] = "Bearer #{@bearer_token}"

		response = http.request(request)
		if (has_token_expired?(response) && !is_retry) then
			@bearer_token = get_bearer_token
			return http_get(url, true)
		end

		return response
	end

	def http_delete(url, is_retry=false)
		http = Net::HTTP.new(@hostname, @port)
		request = Net::HTTP::Delete.new(URI.escape(url))
		request['Authorization'] = "Bearer #{@bearer_token}"
		
		response = http.request(request)
		if (has_token_expired?(request) && !is_retry) then
			@bearer_token = get_bearer_token
			return http_delete(url, true)
		end

		return response
	end

	def http_put(url, document, is_retry=false)
		http = Net::HTTP.new(@hostname, @port)
		request = Net::HTTP::Put.new(URI.escape(url))
		request['Authorization'] = "Bearer #{@bearer_token}"
		request.body = document

		response = http.request(request)
		if (has_token_expired?(request) && !is_retry) then
			@bearer_token = get_bearer_token
			return http_put(url, document, true)
		end

		return response
	end

	def http_post(url, document = nil, is_retry=false)
		http = Net::HTTP.new(@hostname, @port)
		request = Net::HTTP::Post.new(URI.escape(url))
		request['Authorization'] = "Bearer #{@bearer_token}"
		request.body = document unless document.nil?
		
		response = http.request(request)
		if (has_token_expired?(request) && !is_retry) then
			@bearer_token = get_bearer_token
			return http_post(url, document, true)
		end

		return response
	end

	def has_token_expired?(request)
		return request.code == "401" && request['www-authenticate'].include?('The access token is expired')
	end
	
	def get_bearer_token
		request = get_auth_request_hash
		response = prepare_response(request['challenge'])
		public_key = create_rsa_key(request['modulus'], request['exponent'])

		data = "api key name=#{@api_key_name},challenge=#{request['challenge']},response=#{response}"
		response_data = "exponent=#{request['exponent']},modulus=#{request['modulus']},data=#{encrypt(public_key, data)}"
		get_auth_token(response_data)
	end

	def get_auth_request_hash
		http = Net::HTTP.new(@server_url, 8088)
		res = Net::HTTP.post_form(@oauth_endpoint, {})
		
		wwwauth_header = res.header['www-authenticate']
		wwwauth_header[7, wwwauth_header.length - 7] # Remove 'Raven '
			.split(',')
			.map{|str|
				idx = str.index '='
				[str[0, idx].strip.downcase, str[idx+1, str.length]]
			}
			.to_h
	end

	def get_auth_token (response_data)
		req = Net::HTTP::Post.new(@oauth_endpoint.request_uri)
		req.add_field('grant-type', 'client_credentials')
		req.body = response_data
		
		res = Net::HTTP.new(@oauth_endpoint.host, @oauth_endpoint.port).request(req)
		res.body.to_s
	end

	def prepare_response (challenge)
		input = challenge + ";" + @api_key_secret
		Digest::SHA1.base64digest input 
	end

	def create_rsa_key (modulus_base64, exponent_base64)
		key = OpenSSL::PKey::RSA.new
		exponent = OpenSSL::BN.new(Base64.decode64(exponent_base64).unpack("H*").first, 16)
		modulus = OpenSSL::BN.new(Base64.decode64(modulus_base64).unpack("H*").first, 16)
		key.e = exponent
		key.n = modulus
		key
	end

	def encrypt(public_key, data)
		key = SecureRandom.random_bytes(32)
		iv = SecureRandom.random_bytes(16)

		key_and_iv_encrypted = public_key.public_encrypt(key + iv, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
		
		cipher = OpenSSL::Cipher::AES256.new(:CBC)
		cipher.encrypt
		cipher.key = key
		cipher.iv = iv
		encrypted = cipher.update(data) + cipher.final
		
		Base64.encode64 (key_and_iv_encrypted + encrypted)
	end
end