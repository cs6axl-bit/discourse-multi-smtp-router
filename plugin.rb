# frozen_string_literal: true

# name: discourse-multi-smtp-router
# about: Route outgoing emails through multiple SMTP providers configured in SiteSettings. Supports: domain->provider overrides, weighted routing by % (coin flip), equal random routing, optional debug logs, optional async external logging, optional per-domain provider selection via metrics table.
# version: 2.4.5
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
    PROVIDER_SLOTS = 6

    # Headers that other plugins (digest-report2) can read:
    HDR_PROVIDER_ID     = "X-Multi-SMTP-Router-Provider-Id"
    HDR_PROVIDER_SLOT   = "X-Multi-SMTP-Router-Provider-Slot"
    HDR_PROVIDER_WEIGHT = "X-Multi-SMTP-Router-Provider-Weight"
    HDR_ROUTING_REASON  = "X-Multi-SMTP-Router-Routing-Reason"
    HDR_ROUTING_UUID    = "X-Multi-SMTP-Router-UUID"

    METRICS_TABLE = "public.digest_provider_domain_metrics"

    # --------------------
    # Logging helpers (LIKE unsub-update)
    # - /admin/logs reliably shows WARN/ERROR.
    # - So debug logs use WARN too, but only if debug switch is ON.
    # --------------------
    def self.enabled?
      SiteSetting.multi_smtp_router_enabled
    end

    def self.debug_enabled?
      SiteSetting.multi_smtp_router_debug_log_enabled
    end

    def self.debug(msg)
      return unless debug_enabled?
      Rails.logger.warn("[#{PLUGIN_NAME}] DEBUG #{msg}")
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

    # Metrics-based routing switch
    def self.domain_metrics_enabled?
      SiteSetting.multi_smtp_router_domain_metrics_enabled
    rescue
      false
    end

    def self.domain_metrics_cache_ttl
      (SiteSetting.multi_smtp_router_domain_metrics_cache_ttl_seconds || 300).to_i
    rescue
      300
    end

    def self.domain_metrics_pre_random_percent
      v = (SiteSetting.multi_smtp_router_domain_metrics_pre_random_percent || 10).to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    rescue
      10
    end

    def self.domain_metrics_single_row_random_percent
      v = (SiteSetting.multi_smtp_router_domain_metrics_single_row_random_percent || 0).to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    rescue
      0
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
    # Weighted selection
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
    # Metrics-based selection per domain
    # --------------------
    def self.domain_metrics_cache
      @domain_metrics_cache ||= {}
    end

    def self.fetch_domain_metrics_rows(domain)
      d = domain.to_s.downcase.strip
      return [] if d.empty?

      ttl = domain_metrics_cache_ttl
      now = Time.now.to_i

      cached = domain_metrics_cache[d]
      if cached && cached[:expires_at].to_i > now
        return cached[:rows] || []
      end

      rows = []
      begin
        sql = <<~SQL
          SELECT provider_id, open_percent, click_percent
          FROM #{METRICS_TABLE}
          WHERE email_domain = ?
        SQL

        res = ::DB.query(sql, d)

        debug("metrics raw domain=#{d} class=#{res.class} sample=#{res.inspect.to_s[0,200]}")

        ary =
          if res.is_a?(Array)
            res
          elsif res.is_a?(Hash)
            [res]
          elsif (res.is_a?(Class) || res.is_a?(Module))
            warn("metrics lookup returned #{res.class} (not rows) domain=#{d}")
            []
          elsif res.respond_to?(:to_a)
            tmp = res.to_a
            tmp.is_a?(Array) ? tmp : []
          else
            warn("metrics lookup unexpected result class=#{res.class} domain=#{d}")
            []
          end

        ary.each do |r|
          next unless r.respond_to?(:[])

          pid = (r[:provider_id] || r["provider_id"]).to_s.strip
          next if pid.empty?

          rows << {
            provider_id: pid,
            open_percent:  (r[:open_percent]  || r["open_percent"]  || 0).to_f,
            click_percent: (r[:click_percent] || r["click_percent"] || 0).to_f
          }
        end

        debug("metrics parsed domain=#{d} rows=#{rows.length} provider_ids=#{rows.map { |x| x[:provider_id] }.uniq.inspect}")
      rescue => e
        warn("metrics lookup failed domain=#{d}: #{e.class}: #{e.message}")
        rows = []
      end

      domain_metrics_cache[d] = { expires_at: now + ttl, rows: rows }
      rows
    end

    def self.percent_hit?(pct)
      p = pct.to_i
      p = 0 if p < 0
      p = 100 if p > 100
      return false if p <= 0
      return true if p >= 100
      rand(1..100) <= p
    rescue
      false
    end

    def self.choose_provider_by_domain_metrics(message, list)
      domains = extract_recipient_domains(message)
      return [nil, "metrics_no_recipient_domain"] if domains.empty?

      domains.each do |domain|
        pre_pct = domain_metrics_pre_random_percent
        if percent_hit?(pre_pct)
          chosen = list.sample
          return [chosen, "metrics_pre_random(pct=#{pre_pct} domain=#{domain})"] if chosen
        end

        rows = fetch_domain_metrics_rows(domain)

        active_ids = list.map { |p| p[:id].to_s }
        rows = rows.select { |r| active_ids.include?(r[:provider_id].to_s) }

        if rows.empty?
          debug("metrics domain=#{domain} no rows for active providers active_ids=#{active_ids.inspect}")
          next
        end

        if rows.length == 1
          single_pct = domain_metrics_single_row_random_percent
          if percent_hit?(single_pct) && list.length > 1
            chosen = list.sample
            return [chosen, "metrics_single_row_random(pct=#{single_pct} domain=#{domain} only=#{rows[0][:provider_id]})"] if chosen
          end

          provider = find_provider_by_id(rows[0][:provider_id])
          if provider
            return [provider, "metrics_single_row(domain=#{domain} provider_id=#{provider[:id]})"]
          else
            warn("metrics single row provider_id=#{rows[0][:provider_id]} but provider not active anymore")
            next
          end
        end

        rows_sorted = rows.sort_by { |r| [-r[:click_percent].to_f, -r[:open_percent].to_f] }

        top_n = (rows_sorted.length / 2.0).ceil
        top_n = 1 if top_n < 1

        top_rows = rows_sorted.first(top_n)
        chosen = top_rows.sample

        provider = find_provider_by_id(chosen[:provider_id])
        if provider
          reason = "metrics_top50(domain=#{domain} top_n=#{top_n} total=#{rows_sorted.length})"
          return [provider, reason]
        else
          warn("metrics chose provider_id=#{chosen[:provider_id]} but provider not active anymore")
        end
      end

      if list.any?
        p = list.sample
        return [p, "metrics_domain_not_found_fallback_random_all"] if p
      end

      [nil, "metrics_no_active_providers"]
    rescue => e
      warn("choose_provider_by_domain_metrics failed: #{e.class}: #{e.message}")
      [nil, "metrics_exception_fallback"]
    end

    # --------------------
    # Routing decision
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

      # 2) Metrics-based routing per domain
      if domain_metrics_enabled?
        p, reason = choose_provider_by_domain_metrics(message, list)
        return [p, reason] if p
        debug("metrics enabled but did not select provider; continuing to other modes reason=#{reason}")
      end

      # 3) Weighted mode
      if weighted_enabled?
        p, total = choose_weighted_provider(list)
        if p
          return [p, "weighted(total=#{total})"]
        else
          return [nil, "weighted_enabled_but_total_weight_zero"]
        end
      end

      # 4) Equal random
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

      # Preserve existing From display name; only swap email address.
      begin
        existing_from_raw =
          (message.header["From"] && message.header["From"].value.to_s.strip) ||
          message["From"].to_s.strip

        existing_name = nil
        if existing_from_raw && !existing_from_raw.empty?
          begin
            existing_addr = Mail::Address.new(existing_from_raw)
            existing_name = existing_addr.display_name.to_s.strip
            existing_name = nil if existing_name.empty?
          rescue
            existing_name = nil
          end
        end

        provider_from_raw = provider[:from_address].to_s.strip
        if !provider_from_raw.empty?
          provider_email = nil
          begin
            provider_addr = Mail::Address.new(provider_from_raw)
            provider_email = provider_addr.address.to_s.strip
            provider_email = nil if provider_email.empty?
          rescue
            provider_email = nil
          end
          provider_email ||= provider_from_raw

          new_from = Mail::Address.new(provider_email)
          new_from.display_name = existing_name if existing_name && !existing_name.empty?
          message["From"] = new_from.format
        end
      rescue => e
        warn("apply_provider From header update failed: #{e.class}: #{e.message}")
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

    # Stamp provider decision onto message headers
    def self.stamp_headers!(message, uuid:, provider:, reason:)
      return if message.nil?

      message.header[HDR_ROUTING_UUID] = uuid.to_s

      if provider
        message.header[HDR_PROVIDER_ID]     = provider[:id].to_s
        message.header[HDR_PROVIDER_SLOT]   = provider[:slot].to_i.to_s
        message.header[HDR_PROVIDER_WEIGHT] = provider[:weight_percent].to_i.to_s
      else
        message.header[HDR_PROVIDER_ID]     = ""
        message.header[HDR_PROVIDER_SLOT]   = ""
        message.header[HDR_PROVIDER_WEIGHT] = ""
      end

      message.header[HDR_ROUTING_REASON] = reason.to_s
      true
    rescue
      false
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

    ::MultiSmtpRouter.warn("HOOK FIRED type=#{type} to=#{Array(message&.to).compact.map(&:to_s).inspect}")

    
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

    ::MultiSmtpRouter.stamp_headers!(message, uuid: uuid, provider: provider, reason: reason)

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
