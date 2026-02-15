# frozen_string_literal: true

# name: discourse-multi-smtp-router
# about: Route outgoing emails through multiple SMTP providers configured in SiteSettings. Supports: domain->provider overrides, weighted routing by % (coin flip), equal random routing, optional debug logs, optional async external logging.
# version: 2.2.0
# authors: you
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
    PROVIDER_SLOTS = 5

    # --------------------
    # Logging helpers
    # --------------------
    def self.enabled?
      SiteSetting.multi_smtp_router_enabled
    end

    def self.debug_enabled?
      SiteSetting.multi_smtp_router_debug_log_enabled
    end

    def self.debug(msg)
      return unless debug_enabled?
      Rails.logger.info("[#{PLUGIN_NAME}] #{msg}")
    rescue
      # never block sending
    end

    def self.warn(msg)
      Rails.logger.warn("[#{PLUGIN_NAME}] #{msg}")
    rescue
      # never block sending
    end

    # --------------------
    # Global switches
    # --------------------
    def self.random_enabled?
      SiteSetting.multi_smtp_router_random_enabled
    end

    def self.domain_override_enabled?
      SiteSetting.multi_smtp_router_domain_override_enabled
    end

    def self.weighted_enabled?
      SiteSetting.multi_smtp_router_weighted_enabled
    end

    def self.log_to_endpoint_enabled?
      SiteSetting.multi_smtp_router_log_to_endpoint_enabled
    end

    def self.log_endpoint_url
      SiteSetting.multi_smtp_router_log_endpoint_url.to_s.strip
    end

    def self.open_timeout
      (SiteSetting.multi_smtp_router_log_http_open_timeout || 2).to_i
    end

    def self.read_timeout
      (SiteSetting.multi_smtp_router_log_http_read_timeout || 3).to_i
    end

    # --------------------
    # Domain->provider pairs stored as list entries:
    # gmail.com=provider_X
    # yahoo.com=provider_Y
    # --------------------
    def self.domain_provider_map
      raw = Array(SiteSetting.multi_smtp_router_domain_provider_pairs)

      map = {}
      raw.each do |line|
        s = line.to_s.strip
        next if s.empty?

        # accept: "gmail.com=provider_x" or "gmail.com>provider_x" or "gmail.com:provider_x"
        if (m = s.match(/\A([^=:\s>]+)\s*(=|:|>)\s*([A-Za-z0-9_\-]+)\z/))
          domain = m[1].downcase.strip
          provider_id = m[3].strip
          next if domain.empty? || provider_id.empty?
          map[domain] = provider_id
        end
      end

      map
    rescue => e
      warn("domain_provider_map parse failed: #{e.class}: #{e.message}")
      {}
    end

    # --------------------
    # Provider slots (UI-configured)
    # Each has: enabled, id, from, reply_to, smtp..., weight_percent
    # Note: weight can be set even if provider disabled; it will be ignored because we only return enabled providers.
    # --------------------
    def self.providers
      out = []

      (1..PROVIDER_SLOTS).each do |i|
        begin
          enabled = SiteSetting.public_send("multi_smtp_router_p#{i}_enabled")
          next unless enabled

          id = SiteSetting.public_send("multi_smtp_router_p#{i}_id").to_s.strip
          next if id.empty?

          from_addr = SiteSetting.public_send("multi_smtp_router_p#{i}_from_address").to_s.strip
          reply_to  = SiteSetting.public_send("multi_smtp_router_p#{i}_reply_to_address").to_s.strip

          weight = SiteSetting.public_send("multi_smtp_router_p#{i}_weight_percent").to_i
          weight = 0 if weight < 0
          weight = 100 if weight > 100

          smtp_address = SiteSetting.public_send("multi_smtp_router_p#{i}_smtp_address").to_s.strip
          smtp_port    = SiteSetting.public_send("multi_smtp_router_p#{i}_smtp_port").to_i
          smtp_user    = SiteSetting.public_send("multi_smtp_router_p#{i}_smtp_username").to_s
          smtp_pass    = SiteSetting.public_send("multi_smtp_router_p#{i}_smtp_password").to_s
          smtp_auth    = SiteSetting.public_send("multi_smtp_router_p#{i}_smtp_authentication_mode").to_s.strip

          starttls_auto = SiteSetting.public_send("multi_smtp_router_p#{i}_smtp_enable_starttls_auto")
          ssl           = SiteSetting.public_send("multi_smtp_router_p#{i}_smtp_ssl")
          tls           = SiteSetting.public_send("multi_smtp_router_p#{i}_smtp_tls")
          helo_domain   = SiteSetting.public_send("multi_smtp_router_p#{i}_smtp_domain").to_s.strip

          smtp = { address: smtp_address, port: smtp_port }
          smtp[:user_name] = smtp_user unless smtp_user.to_s.empty?
          smtp[:password] = smtp_pass unless smtp_pass.to_s.empty?
          smtp[:authentication] = smtp_auth unless smtp_auth.empty?
          smtp[:enable_starttls_auto] = true if starttls_auto
          smtp[:ssl] = true if ssl
          smtp[:tls] = true if tls
          smtp[:domain] = helo_domain unless helo_domain.empty?

          out << {
            slot: i,
            id: id,
            weight_percent: weight,
            from_address: from_addr,
            reply_to_address: reply_to,
            smtp: smtp
          }
        rescue => e
          warn("provider slot #{i} read failed: #{e.class}: #{e.message}")
        end
      end

      out
    end

    def self.find_provider_by_id(id)
      want = id.to_s.strip
      return nil if want.empty?
      providers.find { |p| p[:id].to_s == want }
    end

    # --------------------
    # Mail parsing
    # --------------------
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

    # --------------------
    # Weighted selection (coin flip / cumulative)
    # - Only uses enabled providers (incoming list)
    # - Uses integer weights (0..100) per provider
    # - If sum is 0 => returns nil
    # --------------------
    def self.choose_weighted_provider(list)
      weighted = list.select { |p| p[:weight_percent].to_i > 0 }
      total = weighted.sum { |p| p[:weight_percent].to_i }
      return [nil, 0] if total <= 0

      r = rand(1..total)
      cum = 0
      weighted.each do |p|
        cum += p[:weight_percent].to_i
        return [p, total] if r <= cum
      end

      [weighted.last, total]
    end

    # --------------------
    # Routing decision
    # Order:
    #  1) domain override
    #  2) weighted
    #  3) equal random
    #  4) none => default SMTP
    # --------------------
    def self.choose_provider(message)
      list = providers
      return [nil, "no_enabled_providers"] if list.empty?

      domains = extract_recipient_domains(message)

      # 1) Domain override wins
      if domain_override_enabled?
        map = domain_provider_map
        if !map.empty?
          domains.each do |d|
            pid = map[d]
            next if pid.nil? || pid.to_s.strip.empty?

            p = find_provider_by_id(pid)
            return [p, "domain_override(#{d}->#{pid})"] if p
            return [nil, "domain_override_provider_missing(#{d}->#{pid})"]
          end
        end
      end

      # 2) Weighted mode
      if weighted_enabled?
        p, total = choose_weighted_provider(list)
        if p
          return [p, "weighted(total=#{total})"]
        else
          # Weights total zero across enabled providers
          return [nil, "weighted_enabled_but_total_weight_zero"]
        end
      end

      # 3) Equal random
      if random_enabled?
        return [list.sample, "random_enabled"]
      end

      [nil, "no_routing_logic_enabled"]
    end

    # --------------------
    # Apply provider to THIS message
    # --------------------
    def self.apply_provider!(message, provider)
      return if message.nil? || provider.nil?

      if provider[:from_address].to_s.strip.length > 0
        message["From"] = provider[:from_address].to_s
      end
      if provider[:reply_to_address].to_s.strip.length > 0
        message["Reply-To"] = provider[:reply_to_address].to_s
      end

      smtp = provider[:smtp] || {}
      smtp.each do |k, v|
        message.delivery_method.settings[k.to_sym] = v
      end
    end

    def self.safe_settings_snapshot(delivery_settings)
      h = (delivery_settings || {}).dup
      h[:password] = "***" if h.key?(:password)
      h
    rescue
      {}
    end

    # --------------------
    # Async external logging
    # --------------------
    def self.enqueue_log(payload)
      return unless log_to_endpoint_enabled?
      return if log_endpoint_url.empty?
      Jobs.enqueue(:multi_smtp_router_log, payload: payload)
    rescue => e
      warn("log enqueue failed: #{e.class}: #{e.message}")
    end
  end

  # ---------------------------
  # Sidekiq job to POST logs
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
  # Main hook: never block sending
  # ---------------------------
  DiscourseEvent.on(:before_email_send) do |*params|
    next unless ::MultiSmtpRouter.enabled?

    message, type = *params

    uuid = SecureRandom.uuid
    to_list = Array(message&.to).compact.map(&:to_s)
    domains = ::MultiSmtpRouter.extract_recipient_domains(message)

    ::MultiSmtpRouter.debug("uuid=#{uuid} type=#{type} to=#{to_list.inspect} domains=#{domains.inspect}")

    provider, reason = ::MultiSmtpRouter.choose_provider(message)

    # If weighted enabled but total weight == 0, optionally fall back to random if random switch is on
    if provider.nil? && reason == "weighted_enabled_but_total_weight_zero"
      if ::MultiSmtpRouter.random_enabled?
        list = ::MultiSmtpRouter.providers
        if list.any?
          provider = list.sample
          reason = "weighted_total_zero_fallback_random"
          ::MultiSmtpRouter.debug("uuid=#{uuid} #{reason} chosen_provider_id=#{provider[:id]}")
        end
      else
        ::MultiSmtpRouter.warn("uuid=#{uuid} weighted enabled but total weight=0 and random disabled; default SMTP will be used")
      end
    end

    if provider
      ::MultiSmtpRouter.debug("uuid=#{uuid} chose provider_id=#{provider[:id]} slot=#{provider[:slot]} reason=#{reason} weight=#{provider[:weight_percent]}")
      ::MultiSmtpRouter.apply_provider!(message, provider)
      ::MultiSmtpRouter.debug(
        "uuid=#{uuid} applied provider_id=#{provider[:id]} from=#{provider[:from_address].inspect} reply_to=#{provider[:reply_to_address].inspect} " \
        "settings_after=#{::MultiSmtpRouter.safe_settings_snapshot(message&.delivery_method&.settings).inspect}"
      )
    else
      ::MultiSmtpRouter.debug("uuid=#{uuid} no provider chosen reason=#{reason} (default SMTP will be used)")
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
        chosen_provider_id: provider ? provider[:id].to_s : nil,
        chosen_provider_slot: provider ? provider[:slot].to_i : nil,
        chosen_provider_weight: provider ? provider[:weight_percent].to_i : nil,
        chosen_from: provider ? provider[:from_address].to_s : nil,
        chosen_reply_to: provider ? provider[:reply_to_address].to_s : nil,
        delivery_settings_after: ::MultiSmtpRouter.safe_settings_snapshot(message&.delivery_method&.settings)
      }
    )
  rescue => e
    ::MultiSmtpRouter.warn("before_email_send failed: #{e.class}: #{e.message}")
  end
end
