module Devise
  module Strategies
    class TwoFactorAuthenticatable < Devise::Strategies::DatabaseAuthenticatable

      def authenticate!
        Rails.logger.warn "!!  two factor authenticate"

        resource = mapping.to.find_for_database_authentication(authentication_hash)
        # We authenticate in two cases:
        # 1. The password and the OTP are correct
        # 2. The password is correct, and OTP is not required for login
        # We check the OTP, then defer to DatabaseAuthenticatable
        if validate(resource) { !resource.otp_required_for_login || 
                                resource.valid_otp?(params[scope]['otp_attempt']) }
          super
        else
          Rails.logger.warn "!!  raising OtpError with resource #{resource}"
          raise Devise::OtpError.new("One-time password required", resource)
        end

        fail(:not_found_in_database) unless resource

        # We want to cascade to the next strategy if this one fails,
        # but database authenticatable automatically halts on a bad password
        @halted = false if @result == :failure
      end
    end
  end
end

Warden::Strategies.add(:two_factor_authenticatable, Devise::Strategies::TwoFactorAuthenticatable)
