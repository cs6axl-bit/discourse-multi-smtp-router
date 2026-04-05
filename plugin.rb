# frozen_string_literal: true

# name: discourse-multi-smtp-router
# about: Route outgoing emails through multiple SMTP providers configured in SiteSettings. Supports: domain->provider overrides, weighted routing by % (coin flip), equal random routing, optional debug logs, optional async external logging, optional per-domain provider selection via metrics table. Supports per-provider domain swap.
# version: 2.6.0
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
    PROVIDER_SLOTS = 8

    # Headers that other plugins can read:
    HDR_PROVIDER_ID     = "X-Multi-SMTP-Router-Provider-Id"
    HDR_PROVIDER_SLOT   = "X-Multi-SMTP-Router-Provider-Slot"
    HDR_PROVIDER_WEIGHT = "X-Multi-SMTP-Router-Provider-Weight"
    HDR_ROUTING_REASON  = "X-Multi-SMTP-Router-Routing-Reason"
    HDR_ROUTING_UUID    = "X-Multi-SMTP-Router-UUID"

    METRICS_TABLE = "public.digest_provider_domain_metrics"

    # ONE shared key for the whole table (L2, cross-process)
    METRICS_ALL_CACHE_KEY = "#{PLUGIN_NAME}:metrics:all:v1"

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

    # cache TTL seconds for metrics lookup
    def self.domain_metrics_cache_ttl
      (SiteSetting.multi_smtp_router_domain_metrics_cache_ttl_seconds || 2700).to_i # 45 min default
    rescue
      2700
    end

    # % of times to skip metrics and randomize across active providers
    def self.domain_metrics_pre_random_percent
      v = (SiteSetting.multi_smtp_router_domain_metrics_pre_random_percent || 10).to_i
      v = 0 if v < 0
      v = 100 if v > 100
      v
    rescue
      10
    end

    # If metrics yields exactly 1 row for a domain, % of times to randomize anyway (when >1 provider active)
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
    # Domain override pairs stored as list entries:
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

          allowed_statuses = SiteSetting
            .public_send("multi_smtp_router_p#{i}_allowed_verification_statuses")
            .to_s.split(",").map(&:strip).reject(&:empty?)

          out << {
            slot: i,
            id: id,
            weight_percent: weight,
            from_address: from_addr,
            reply_to_address: reply_to,
            smtp: smtp,
            allowed_verification_statuses: allowed_statuses
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
    # L1 (per-process) + L2 (Discourse.cache, cross-process) whole-table cache
    # map shape:
    #   { "gmail.com" => [ {provider_id:, open_percent:, click_percent:}, ... ], ... }
    # --------------------
    def self.metrics_all_l1
      @metrics_all_l1 ||= { expires_at: 0, map: nil }
    end

    def self.fetch_all_domain_metrics_map
      ttl = domain_metrics_cache_ttl.to_i
      ttl = 2700 if ttl <= 0

      now = Time.now.to_i
      l1 = metrics_all_l1

      # L1 hot-path (no Redis)
      if l1[:map].is_a?(Hash) && l1[:expires_at].to_i > now
        return l1[:map]
      end

      # L2 shared (across processes)
      map = Discourse.cache.fetch(METRICS_ALL_CACHE_KEY, expires_in: ttl.seconds) do
        built = {}

        begin
          sql = <<~SQL
            SELECT email_domain, provider_id, open_percent, click_percent
            FROM #{METRICS_TABLE}
          SQL

          res = ::DB.query(sql)
          debug("metrics_all raw class=#{res.class} sample=#{res.inspect.to_s[0,200]}")

          ary =
            if res.is_a?(Array)
              res
            elsif res.is_a?(Hash)
              [res]
            elsif res.respond_to?(:to_a)
              tmp = res.to_a
              tmp.is_a?(Array) ? tmp : []
            else
              warn("metrics_all unexpected result class=#{res.class}")
              []
            end

          get = lambda do |row, key|
            k = key.to_s

            if row.respond_to?(:[])
              begin
                v = row[key.to_sym]
                return v unless v.nil?
              rescue
              end
              begin
                v = row[k]
                return v unless v.nil?
              rescue
              end
            end

            if row.respond_to?(key)
              begin
                v = row.public_send(key)
                return v unless v.nil?
              rescue
              end
            end
            if row.respond_to?(k)
              begin
                v = row.public_send(k)
                return v unless v.nil?
              rescue
              end
            end

            iv = :"@#{k}"
            if row.respond_to?(:instance_variable_defined?) && row.instance_variable_defined?(iv)
              begin
                return row.instance_variable_get(iv)
              rescue
              end
            end

            nil
          end

          total_rows = 0
          ary.each do |r|
            domain = get.call(r, :email_domain).to_s.downcase.strip
            next if domain.empty?

            pid = get.call(r, :provider_id).to_s.strip
            next if pid.empty?

            op = get.call(r, :open_percent)
            cp = get.call(r, :click_percent)

            built[domain] ||= []
            built[domain] << {
              provider_id: pid,
              open_percent:  (op.nil? ? 0 : op).to_f,
              click_percent: (cp.nil? ? 0 : cp).to_f
            }
            total_rows += 1
          end

          debug("metrics_all parsed domains=#{built.keys.length} rows_total=#{total_rows}")
        rescue => e
          warn("metrics_all lookup failed: #{e.class}: #{e.message}")
          built = {}
        end

        built
      end

      map = {} unless map.is_a?(Hash)

      # refresh L1 from L2 result
      @metrics_all_l1 = { expires_at: now + ttl, map: map }

      map
    rescue => e
      warn("metrics_all cache fetch failed: #{e.class}: #{e.message}")
      {}
    end

    def self.fetch_domain_metrics_rows(domain)
      d = domain.to_s.downcase.strip
      return [] if d.empty?

      map = fetch_all_domain_metrics_map
      map[d] || []
    rescue => e
      warn("fetch_domain_metrics_rows failed domain=#{domain}: #{e.class}: #{e.message}")
      []
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

        # filter to providers that are currently active in this plugin
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

        # Rank: click_percent (primary) then open_percent (secondary)
        rows_sorted = rows.sort_by { |r| [-r[:click_percent].to_f, -r[:open_percent].to_f] }

        # Top 50% (ceil). Ensure at least 1.
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

      # No domain hit -> random among all active providers
      if list.any?
        p = list.sample

        # A2: only WARN this fallback when debug is enabled (silent otherwise)
        if debug_enabled?
          warn("metrics fallback random_all domains=#{domains.inspect} (no matching active provider rows)")
        end

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

      # Filter pool by email verification status
      if verification_enabled?
        email  = Array(message&.to).first.to_s
        status = fetch_verification_status(email)
        debug("verification email=#{email} status=#{status}")

        list = filter_providers_by_verification(list, status)

        if list.empty?
          return [nil, "verification_no_pool(email=#{email} status=#{status})"]
        end
      end

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

      # Preserve existing From display name; only swap email address to provider's from_address email.
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

    # Stamp provider decision onto message headers so other plugins can read it later
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

    # ============================================================
    # Email verification-based pool filtering
    # ============================================================

    def self.verification_enabled?
      SiteSetting.multi_smtp_router_verification_enabled
    rescue
      false
    end

    def self.verification_cache_enabled?
      SiteSetting.multi_smtp_router_verification_cache_enabled
    rescue
      true
    end

    def self.verification_cache_ttl
      days = (SiteSetting.multi_smtp_router_verification_cache_ttl_days || 30).to_i
      days = 1   if days < 1
      days = 365 if days > 365
      days * 86_400
    rescue
      30 * 86_400
    end

    def self.verification_table
      SiteSetting.multi_smtp_router_verification_table.to_s.strip.presence || "email_verifications"
    rescue
      "email_verifications"
    end

    def self.verification_email_column
      SiteSetting.multi_smtp_router_verification_email_column.to_s.strip.presence || "email"
    rescue
      "email"
    end

    def self.verification_status_column
      SiteSetting.multi_smtp_router_verification_status_column.to_s.strip.presence || "status"
    rescue
      "status"
    end

    def self.verification_default_status
      SiteSetting.multi_smtp_router_verification_default_status.to_s.strip.presence || "unknown"
    rescue
      "unknown"
    end

    def self.verification_cache_key(email)
      "#{PLUGIN_NAME}:verif:#{email.to_s.downcase.strip}"
    end

    def self.fetch_verification_status(email)
      e = email.to_s.downcase.strip
      return verification_default_status if e.empty?

      if verification_cache_enabled?
        cached = Discourse.cache.read(verification_cache_key(e))
        return cached if cached
      end

      status = begin
        tbl  = verification_table
        ecol = verification_email_column
        scol = verification_status_column

        row = ::DB.query_single(
          "SELECT #{scol} FROM #{tbl} WHERE #{ecol} = :email LIMIT 1",
          email: e
        )
        row.first.to_s.strip.presence || verification_default_status
      rescue => ex
        warn("fetch_verification_status db failed email=#{e}: #{ex.class}: #{ex.message}")
        verification_default_status
      end

      if verification_cache_enabled?
        Discourse.cache.write(verification_cache_key(e), status, expires_in: verification_cache_ttl)
      end

      status
    rescue => e
      warn("fetch_verification_status failed: #{e.class}: #{e.message}")
      verification_default_status
    end

    def self.filter_providers_by_verification(list, status)
      list.select do |p|
        allowed = p[:allowed_verification_statuses]
        allowed.empty? || allowed.include?(status)
      end
    end

    # ============================================================
    # Per-provider domain swap
    # ============================================================

    DS_TEXT_URL_REGEX = %r{https?://[^\s<>"'()]+}i

    DS_HEADERS_TO_SWAP = %w[
      List-Unsubscribe
      List-Help
      List-Subscribe
      List-Owner
    ].freeze

    def self.provider_domain_swap_config(slot)
      i = slot.to_i
      {
        enabled:    SiteSetting.public_send("multi_smtp_router_p#{i}_domain_swap_enabled"),
        targets:    SiteSetting.public_send("multi_smtp_router_p#{i}_domain_swap_targets").to_s,
        html_links: SiteSetting.public_send("multi_smtp_router_p#{i}_domain_swap_html_links"),
        text_links: SiteSetting.public_send("multi_smtp_router_p#{i}_domain_swap_text_links"),
        headers:    SiteSetting.public_send("multi_smtp_router_p#{i}_domain_swap_headers"),
        message_id: SiteSetting.public_send("multi_smtp_router_p#{i}_domain_swap_message_id"),
        everywhere: SiteSetting.public_send("multi_smtp_router_p#{i}_domain_swap_everywhere"),
      }
    rescue => e
      warn("provider_domain_swap_config slot=#{slot} failed: #{e.class}: #{e.message}")
      { enabled: false }
    end

    def self.ds_origin_host
      URI.parse(Discourse.base_url.to_s).host.to_s.strip.downcase
    rescue
      ""
    end

    def self.ds_normalize_host(s)
      x = s.to_s.strip
      return "" if x.empty?
      x = x.sub(%r{\Ahttps?://}i, "")
      x = x.split("/").first.to_s
      x = x.split("?").first.to_s
      x = x.split("#").first.to_s
      x.downcase
    rescue
      ""
    end

    def self.ds_pick_target(targets_str)
      parts = targets_str.to_s.split(/[|\n,]/).map(&:strip).reject(&:empty?)
      return "" if parts.empty?
      parts.sample.to_s
    rescue
      ""
    end

    def self.ds_rewrite_host(host, target)
      h = host.to_s
      return nil if h.empty?

      o = ds_origin_host
      t = ds_normalize_host(target)
      return nil if o.empty? || t.empty?
      return nil if ds_normalize_host(h) == t

      h_lc = h.downcase
      if h_lc == o
        return target.to_s.strip
      end

      suffix = ".#{o}"
      if h_lc.end_with?(suffix)
        prefix = h[0, h.length - suffix.length]
        return "#{prefix}.#{target.to_s.strip}"
      end

      nil
    rescue
      nil
    end

    def self.ds_rewrite_url(url_str, base, target)
      u = url_str.to_s.strip
      return nil if u.empty?
      return nil if u.start_with?("mailto:", "tel:", "sms:", "#")

      abs = u.start_with?("/") ? (base.to_s + u) : u

      begin
        uri = URI.parse(abs)
      rescue
        return nil
      end

      return nil unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
      return nil if uri.host.to_s.empty?

      new_host = ds_rewrite_host(uri.host, target)
      return nil unless new_host

      uri.host = new_host
      uri.to_s
    rescue
      nil
    end

    def self.ds_rewrite_srcset(srcset, base, target)
      raw = srcset.to_s
      return nil if raw.strip.empty?

      parts = raw.split(",").map(&:strip).reject(&:empty?)
      return nil if parts.empty?

      changed = false
      new_parts = parts.map do |p|
        tokens = p.split(/\s+/, 2)
        url  = tokens[0].to_s
        rest = tokens.length > 1 ? tokens[1].to_s : ""

        rewritten = ds_rewrite_url(url, base, target)
        if rewritten
          changed = true
          rest.empty? ? rewritten : "#{rewritten} #{rest}"
        else
          p
        end
      end

      changed ? new_parts.join(", ") : nil
    rescue
      nil
    end

    def self.ds_swap_html!(message, base, target, cfg)
      return unless message.respond_to?(:html_part) && message.html_part

      hp   = message.html_part
      html = hp.body&.decoded
      return if html.nil? || html.empty?

      begin
        doc     = Nokogiri::HTML::Document.parse(html)
        changed = false

        if cfg[:html_links] || cfg[:everywhere]
          doc.css("a[href]").each do |a|
            new_url = ds_rewrite_url(a["href"].to_s, base, target)
            next unless new_url
            a["href"] = new_url
            changed = true
          end
        end

        if cfg[:everywhere]
          [
            ["img[src]",      "src"],
            ["img[data-src]", "data-src"],
            ["source[src]",   "src"],
            ["video[src]",    "src"],
            ["audio[src]",    "src"],
            ["iframe[src]",   "src"],
            ["link[href]",    "href"],
            ["form[action]",  "action"],
            ["video[poster]", "poster"],
          ].each do |sel, attr|
            doc.css(sel).each do |node|
              new_url = ds_rewrite_url(node[attr].to_s, base, target)
              next unless new_url
              node[attr] = new_url
              changed = true
            end
          end

          doc.css("img[srcset],source[srcset]").each do |node|
            new_srcset = ds_rewrite_srcset(node["srcset"].to_s, base, target)
            next unless new_srcset
            node["srcset"] = new_srcset
            changed = true
          end
        end

        hp.body = doc.to_html if changed
      rescue => e
        warn("domain_swap html failed: #{e.class}: #{e.message}")
      end
    end

    def self.ds_strip_trailing_punct(url)
      u      = url.to_s
      suffix = +""
      while u.length > 0 && u[-1].match?(/[)\].,;:!?]/)
        suffix.prepend(u[-1])
        u = u[0..-2]
      end
      [u, suffix]
    rescue
      [url.to_s, ""]
    end

    def self.ds_swap_text_url(url, target)
      core, suffix = ds_strip_trailing_punct(url)

      begin
        uri = URI.parse(core)
      rescue
        return url
      end

      return url unless uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
      return url if uri.host.to_s.empty?

      new_host = ds_rewrite_host(uri.host, target)
      return url unless new_host

      uri.host = new_host
      uri.to_s + suffix
    rescue
      url
    end

    def self.ds_swap_text!(message, target)
      return unless message.respond_to?(:text_part) && message.text_part

      tp   = message.text_part
      text = tp.body&.decoded
      return if text.nil? || text.empty?

      changed = false
      out = text.to_s.gsub(DS_TEXT_URL_REGEX) do |found|
        swapped = ds_swap_text_url(found, target)
        changed = true if swapped != found
        swapped
      end

      tp.body = out if changed
    rescue => e
      warn("domain_swap text failed: #{e.class}: #{e.message}")
    end

    def self.ds_swap_headers!(message, target)
      return unless message.respond_to?(:header) && message.header

      DS_HEADERS_TO_SWAP.each do |hname|
        begin
          fields = message.header.fields.select { |f| f.name.to_s.casecmp?(hname) }
          next if fields.empty?

          fields.each do |f|
            old_val = f.value.to_s
            next if old_val.strip.empty?

            new_val = old_val.gsub(DS_TEXT_URL_REGEX) { |u| ds_swap_text_url(u, target) }
            next if new_val == old_val

            f.value = new_val
          end
        rescue
          next
        end
      end
    rescue => e
      warn("domain_swap headers failed: #{e.class}: #{e.message}")
    end

    def self.ds_swap_message_id!(message, target)
      return unless message.respond_to?(:header) && message.header

      # Optionally force lazy generation before reading (needed for some email types
      # where ActionMailer generates Message-ID on first access via .message_id).
      if SiteSetting.multi_smtp_router_domain_swap_message_id_force_generate rescue false
        _ = message.message_id if message.respond_to?(:message_id)
      end

      # Use .to_s on the header field (not .value) — triggers full encoding/lazy generation.
      # Falls back to header["Message-ID"] if field enumeration yields nothing.
      raw = begin
        fields = message.header.fields.select do |f|
          f.name.to_s.casecmp?("Message-ID") || f.name.to_s.casecmp?("Message-Id")
        end
        if fields.any?
          fields.first.to_s.strip
        else
          (message.header["Message-ID"]).to_s.strip
        end
      end

      return if raw.empty?

      # Strip surrounding <> then split on first @
      s = raw.start_with?("<") && raw.end_with?(">") ? raw[1..-2].strip : raw
      return unless s.include?("@")

      local, dom = s.split("@", 2)
      local = local.to_s.strip
      dom   = dom.to_s.strip
      return if local.empty? || dom.empty?

      new_host = ds_rewrite_host(dom, target)
      return unless new_host

      new_mid = "<#{local}@#{new_host}>"

      message.header["Message-ID"] = new_mid

      if message.respond_to?(:message_id=)
        begin
          message.message_id = new_mid
        rescue
        end
      end

      debug("domain_swap message_id: #{raw} -> #{new_mid}")
    rescue => e
      warn("domain_swap message_id failed: #{e.class}: #{e.message}")
    end

    def self.process_domain_swap!(message, provider)
      return unless provider

      cfg = provider_domain_swap_config(provider[:slot])
      return unless cfg[:enabled]

      target = ds_pick_target(cfg[:targets])
      return if target.empty?

      base = Discourse.base_url.to_s

      ds_swap_html!(message, base, target, cfg)
      ds_swap_text!(message, target)       if cfg[:text_links] || cfg[:everywhere]
      ds_swap_headers!(message, target)    if cfg[:headers]
      ds_swap_message_id!(message, target) if cfg[:message_id]

      debug("domain_swap applied provider_id=#{provider[:id]} target=#{target}")
    rescue => e
      warn("process_domain_swap! failed: #{e.class}: #{e.message}")
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

    if reason&.start_with?("verification_no_pool")
      ::MultiSmtpRouter.warn("uuid=#{uuid} skipping send: #{reason}")
      message.perform_deliveries = false
      next
    end

    if provider
      ::MultiSmtpRouter.debug("uuid=#{uuid} chose provider_id=#{provider[:id]} slot=#{provider[:slot]} reason=#{reason} weight=#{provider[:weight_percent]}")
      ::MultiSmtpRouter.apply_provider!(message, provider)
      ::MultiSmtpRouter.debug(
        "uuid=#{uuid} applied provider_id=#{provider[:id]} from=#{provider[:from_address].inspect} reply_to=#{provider[:reply_to_address].inspect} " \
        "settings_after=#{::MultiSmtpRouter.safe_settings_snapshot(message&.delivery_method&.settings).inspect}"
      )
      ::MultiSmtpRouter.process_domain_swap!(message, provider)
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
