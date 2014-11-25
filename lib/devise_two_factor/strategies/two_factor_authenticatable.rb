module Devise
  module Strategies
    class TwoFactorAuthenticatable < Devise::Strategies::DatabaseAuthenticatable

      def authenticate!
        resource = mapping.to.find_for_database_authentication(authentication_hash)
        # We authenticate in two cases:
        # 1. The password and the OTP are correct
        # 2. The password is correct, and OTP is not required for login
        # We check the OTP, then defer to DatabaseAuthenticatable
        
        otp_secret = params[scope]['otp_secret']
        otp_attempt = params[scope]['otp_attempt']
        if validate(resource) { !resource.otp_required_for_login || 
                                (!resource.mfa_set? && resource.valid_otp?(otp_attempt, otp_secret: otp_secret)) || 
                                resource.valid_otp?(otp_attempt) }
          if otp_secret.present? && !resource.mfa_set?
            resource.otp_secret = otp_secret
            resource.save
          end

          super

        else
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
