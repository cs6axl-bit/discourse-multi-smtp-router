# frozen_string_literal: true

# name: discourse-multi-smtp-router
# about: Route outgoing emails through multiple SMTP providers (random among active, optional domain override), optionally override From/Reply-To per provider, optionally log routing to Discourse logs and/or an external endpoint asynchronously.
# version: 1.0.0
# authors: you
# url: https://github.com/YOURUSER/discourse-multi-smtp-router
# required_version: 3.0.0

enabled_site_setting :multi_smtp_router_enabled

after_initialize do
  require "net/http"
  require "uri"
  require "json"
  require "securerandom"
  require "time"

  module ::MultiSmtpRouter
    PLUGIN_NAME = "discourse-multi-smtp-router"

    def self.enabled?
      SiteSetting.multi_smtp_router_enabled
    end

    def self.debug_enabled?
      SiteSetting.multi_smtp_router_debug_log_enabled
    end

    def self.log_to_endpoint_enabled?
      SiteSetting.multi_smtp_router_log_to_endpoint_enabled
    end

    def self.debug(msg)
      return unless debug_enabled?
      Rails.logger.info("[#{PLUGIN_NAME}] #{msg}")
    rescue
      # never fail
    end

    def self.warn(msg)
      Rails.logger.warn("[#{PLUGIN_NAME}] #{msg}")
    rescue
      # never fail
    end

    def self.read_timeout
      (SiteSetting.multi_smtp_router_log_http_read_timeout || 3).to_i
    end

    def self.open_timeout
      (SiteSetting.multi_smtp_router_log_http_open_timeout || 2).to_i
    end

    # ---------- Settings parsing ----------

    def self.override_domains
      # type: list => usually array; still normalize
      v = SiteSetting.multi_smtp_router_override_domains
      Array(v).map { |s| s.to_s.downcase.strip }.reject(&:empty?).uniq
    rescue
      []
    end

    def self.override_provider_id
      SiteSetting.multi_smtp_router_override_provider_id.to_s.strip
    rescue
      ""
    end

    def self.random_enabled?
      SiteSetting.multi_smtp_router_random_enabled
    end

    def self.domain_override_enabled?
      SiteSetting.multi_smtp_router_domain_override_enabled
    end

    def self.providers_raw_json
      SiteSetting.multi_smtp_router_providers_json.to_s
    end

    def self.parse_providers
      raw = providers_raw_json.strip
      return [] if raw.empty?

      parsed = JSON.parse(raw)
      return [] unless parsed.is_a?(Array)

      parsed.map do |p|
        next unless p.is_a?(Hash)

        {
          id: p["id"].to_s,
          is_active: p["is_active"].to_i,
          from_address: p["from_address"].to_s,
          reply_to_address: p["reply_to_address"].to_s,
          smtp: (p["smtp"].is_a?(Hash) ? p["smtp"] : {})
        }
      end.compact
    rescue => e
      warn("providers_json parse failed: #{e.class}: #{e.message}")
      []
    end

    def self.active_providers
      parse_providers.select { |p| p[:is_active].to_i == 1 && p[:id].to_s.strip.length > 0 }
    end

    def self.find_provider(id)
      want = id.to_s.strip
      return nil if want.empty?
      parse_providers.find { |p| p[:id].to_s == want }
    end

    # ---------- Mail helpers ----------

    def self.extract_recipient_domains(message)
      tos = Array(message&.to).compact
      tos.map do |addr|
        s = addr.to_s.downcase
        if (m = s.match(/([a-z0-9._%+\-]+)@([a-z0-9.\-]+\.[a-z]{2,})/i))
          m[2].downcase
        else
          nil
        end
      end.compact.uniq
    end

    def self.safe_settings_snapshot(delivery_settings)
      h = (delivery_settings || {}).dup
      # mask common secrets
      if h.key?(:password)
        h[:password] = "***"
      end
      if h.key?("password")
        h["password"] = "***"
      end
      h
    rescue
      {}
    end

    def self.choose_provider(message)
      active = active_providers
      return [nil, "no_active_providers"] if active.empty?

      domains = extract_recipient_domains(message)

      # Logic B: domain override (higher priority)
      if domain_override_enabled?
        ods = override_domains
        if !ods.empty? && domains.any? { |d| ods.include?(d) }
          forced_id = override_provider_id
          forced = find_provider(forced_id)
          if forced && forced[:is_active].to_i == 1
            return [forced, "domain_override"]
          else
            return [nil, "override_provider_missing_or_inactive"]
          end
        end
      end

      # Logic A: random among active
      if random_enabled?
        return [active.sample, "random_active"]
      end

      [nil, "no_routing_logic_enabled"]
    end

    def self.apply_provider!(message, provider)
      return if message.nil? || provider.nil?

      # From / Reply-To
      if provider[:from_address].to_s.strip.length > 0
        message["From"] = provider[:from_address].to_s
      end
      if provider[:reply_to_address].to_s.strip.length > 0
        message["Reply-To"] = provider[:reply_to_address].to_s
      end

      # SMTP settings for THIS message
      smtp = provider[:smtp] || {}
      smtp.each do |k, v|
        message.delivery_method.settings[k.to_sym] = v
      end
    end

    def self.enqueue_log(payload)
      return unless log_to_endpoint_enabled?
      Jobs.enqueue(:multi_smtp_router_log, payload: payload)
    rescue => e
      warn("log enqueue failed: #{e.class}: #{e.message}")
    end
  end

  # ---------------------------
  # Async logging job
  # ---------------------------
  module ::Jobs
    class MultiSmtpRouterLog < ::Jobs::Base
      def execute(args)
        payload = args[:payload] || {}
        url = SiteSetting.multi_smtp_router_log_endpoint_url.to_s.strip
        return if url.empty?

        uri = URI.parse(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")
        http.open_timeout = ::MultiSmtpRouter.open_timeout
        http.read_timeout = ::MultiSmtpRouter.read_timeout

        req = Net::HTTP::Post.new(uri.request_uri)
        req["Content-Type"] = "application/json"
        req.body = JSON.generate(payload)

        http.request(req)
      rescue => e
        ::MultiSmtpRouter.warn("log post failed: #{e.class}: #{e.message}")
      end
    end
  end

  # ---------------------------
  # Main hook
  # ---------------------------
  DiscourseEvent.on(:before_email_send) do |*params|
    next unless ::MultiSmtpRouter.enabled?

    message, type = *params

    uuid = SecureRandom.uuid
    to_list = Array(message&.to).compact.map(&:to_s)
    domains = ::MultiSmtpRouter.extract_recipient_domains(message)

    ::MultiSmtpRouter.debug("uuid=#{uuid} type=#{type} to=#{to_list.inspect} domains=#{domains.inspect}")

    chosen_provider, reason = ::MultiSmtpRouter.choose_provider(message)

    if chosen_provider
      ::MultiSmtpRouter.debug("uuid=#{uuid} chose provider_id=#{chosen_provider[:id]} reason=#{reason}")
      ::MultiSmtpRouter.apply_provider!(message, chosen_provider)
      ::MultiSmtpRouter.debug(
        "uuid=#{uuid} applied provider_id=#{chosen_provider[:id]} " \
        "from=#{chosen_provider[:from_address].to_s.inspect} reply_to=#{chosen_provider[:reply_to_address].to_s.inspect} " \
        "settings_after=#{::MultiSmtpRouter.safe_settings_snapshot(message&.delivery_method&.settings).inspect}"
      )
    else
      ::MultiSmtpRouter.debug("uuid=#{uuid} no provider chosen reason=#{reason} (leaving default SMTP)")
    end

    ::MultiSmtpRouter.enqueue_log(
      {
        plugin: ::MultiSmtpRouter::PLUGIN_NAME,
        uuid: uuid,
        at_utc: Time.now.utc.iso8601,
        email_type: type.to_s,
        to: to_list,
        recipient_domains: domains,
        routing_reason: reason,
        chosen_provider_id: chosen_provider ? chosen_provider[:id].to_s : nil,
        chosen_from: chosen_provider ? chosen_provider[:from_address].to_s : nil,
        chosen_reply_to: chosen_provider ? chosen_provider[:reply_to_address].to_s : nil,
        delivery_settings_after: ::MultiSmtpRouter.safe_settings_snapshot(message&.delivery_method&.settings)
      }
    )
  rescue => e
    ::MultiSmtpRouter.warn("before_email_send failed: #{e.class}: #{e.message}")
  end
end
