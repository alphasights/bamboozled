require 'json'
require 'active_support/core_ext/hash/indifferent_access'

module Bamboozled
  module API
    class Base
      attr_reader :subdomain, :api_key

      def initialize(subdomain, api_key)
        @subdomain, @api_key = subdomain, api_key
      end

      protected
        def request(method, path, options = {})
          params = {
            path:    path,
            options: options,
            method:  method
          }

          strio = StringIO.new
          log = Logger.new strio

          httparty_options = {
            query:  options[:query],
            body:   options[:body],
            format: :plain,
            ssl_version: :TLSv1_2,
            debug_output: log,
            basic_auth: auth,
            headers: {
              "Accept"       => "application/json",
              "User-Agent"   => "Bamboozled/#{Bamboozled::VERSION}"
            }.update(options[:headers] || {})
          }

          response = HTTParty.send(method, "#{path_prefix}#{path}", httparty_options)
          params[:response] = response.inspect.to_s

          case response.code
          when 200..201
            begin
              if ENV.fetch('BAMBOO_REQUEST_LOGGING_ENBALED', false) == "true"
                encoded_auth_to_remove = Base64.encode64("#{auth[:username]}:#{auth[:password]}").chomp

                employee_number_match = /(employeeNumber\D*)(\d*)/.match(httparty_options[:body])
                employee_number = employee_number_match[2].presence if employee_number_match.present?

                work_email_match = /([a-zA-Z\.]*@alphasights.com)/.match(httparty_options[:body])
                work_email = work_email_match[1].presence if work_email_match.present?

                bamboo_id_match = /(employees\/)(\d*)/.match(path)
                bamboo_id = bamboo_id_match[2].presence if bamboo_id_match.present?

                request_log = method.to_s == "get" ? nil : strio.string.gsub(encoded_auth_to_remove, "REDACTED-AUTH")

                BambooRequestLog.create(
                  response_headers: response.headers.to_json,
                  response_timestamp: response["date"],
                  request_method: method.to_s,
                  request_path: "#{path_prefix}#{path}",
                  request_body: httparty_options[:body],
                  raw_httparty_request_log: request_log,
                  involving_employee_number:  employee_number,
                  involving_work_email: work_email,
                  involving_bamboo_id: bamboo_id
                )
              end

              if response.body.to_s.empty?
                {"headers" => response.headers, "code" => "200", "message" => "ok"}.with_indifferent_access
              else
                json = JSON.parse(response.body)
                if json.is_a?(Array)
                  JSON.parse(response.body).map(&:with_indifferent_access)
                else
                  JSON.parse(response.body).with_indifferent_access
                end
              end
            rescue
              MultiXml.parse(response, symbolize_keys: true)
            end
          when 400
            raise Bamboozled::BadRequest.new(response, params, 'The request was invalid or could not be understood by the server. Resubmitting the request will likely result in the same error.')
          when 401
            raise Bamboozled::AuthenticationFailed.new(response, params, 'Your API key is missing.')
          when 403
            raise Bamboozled::Forbidden.new(response, params, 'The application is attempting to perform an action it does not have privileges to access. Verify your API key belongs to an enabled user with the required permissions.')
          when 404
            raise Bamboozled::NotFound.new(response, params, 'The resource was not found with the given identifier. Either the URL given is not a valid API, or the ID of the object specified in the request is invalid.')
          when 406
            raise Bamboozled::NotAcceptable.new(response, params, 'The request contains references to non-existent fields.')
          when 409
            raise Bamboozled::Conflict.new(response, params, 'The request attempts to create a duplicate. For employees, duplicate emails are not allowed. For lists, duplicate values are not allowed.')
          when 429
            raise Bamboozled::LimitExceeded.new(response, params, 'The account has reached its employee limit. No additional employees could be added.')
          when 500
            raise Bamboozled::InternalServerError.new(response, params, 'The server encountered an error while processing your request and failed.')
          when 502
            raise Bamboozled::GatewayError.new(response, params, 'The load balancer or web server had trouble connecting to the Bamboo app. Please try the request again.')
          when 503
            raise Bamboozled::ServiceUnavailable.new(response, params, 'The service is temporarily unavailable. Please try the request again.')
          else
            raise Bamboozled::InformBamboo.new(response, params, 'An error occurred that we do not now how to handle. Please contact BambooHR.')
          end
        end

        def auth
          { username: api_key, password: "x" }
        end

        def path_prefix
          "https://api.bamboohr.com/api/gateway.php/#{subdomain}/v1/"
        end
    end
  end
end
