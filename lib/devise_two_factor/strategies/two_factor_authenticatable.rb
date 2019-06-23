module Devise
  module Strategies
    class TwoFactorAuthenticatable < Devise::Strategies::DatabaseAuthenticatable

      def authenticate!
        resource = mapping.to.find_for_database_authentication(authentication_hash)
        # We authenticate in three cases:
        # 1. The password and the OTP are correct
        # 2. The password is correct, the OTP matches the given OTP secret and no previous secret exists.
        # 3. The password is correct, and OTP is not required for login
        # We check the OTP, then defer to DatabaseAuthenticatable
        if validate(resource) { validate_otp(resource) }
          super
        else
          raise Devise::OtpError.new("One-time password required", resource)
        end

        fail(Devise.paranoid ? :invalid : :not_found_in_database) unless resource

        # We want to cascade to the next strategy if this one fails,
        # but database authenticatable automatically halts on a bad password
        @halted = false if @result == :failure
      end

      def validate_otp(resource)
        return true unless resource.otp_required_for_login
        return if params[scope]['otp_attempt'].nil?
        if !resource.mfa_set? && resource.validate_and_consume_otp!(params[scope]['otp_attempt'], otp_secret: params[scope]['otp_secret'])
          resource.otp_secret = params[scope]['otp_secret']
          resource.save
          return true
        end
        resource.validate_and_consume_otp!(params[scope]['otp_attempt'])
      end
    end
  end
end

Warden::Strategies.add(:two_factor_authenticatable, Devise::Strategies::TwoFactorAuthenticatable)
