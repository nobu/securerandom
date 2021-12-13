# -*- coding: us-ascii -*-
# frozen_string_literal: true

require 'random/formatter'

# == Secure random number generator interface.
#
# This library is an interface to secure random number generators which are
# suitable for generating session keys in HTTP cookies, etc.
#
# You can use this library in your application by requiring it:
#
#   require 'securerandom'
#
# It supports the following secure random number generators:
#
# * openssl
# * /dev/urandom
# * Win32
#
# SecureRandom is extended by the Random::Formatter module which
# defines the following methods:
#
# * alphanumeric
# * base64
# * choose
# * gen_random
# * hex
# * rand
# * random_bytes
# * random_number
# * urlsafe_base64
# * uuid
#
# These methods are usable as class methods of SecureRandom such as
# +SecureRandom.hex+.
#
# If a secure random number generator is not available,
# +NotImplementedError+ is raised.

module SecureRandom

  # The version
  VERSION = "0.3.0"

  class << self
    # Returns a random binary string containing +size+ bytes.
    #
    # See Random.bytes
    def bytes(n)
      return gen_random(n)
    end

    private

    # :stopdoc:

    # Implementation using OpenSSL
    def gen_random_openssl(n)
      return OpenSSL::Random.random_bytes(n)
    end

    # Implementation using system random device
    def gen_random_urandom(n)
      ret = Random.urandom(n)
      unless ret
        raise NotImplementedError, "No random device"
      end
      unless ret.length == n
        raise NotImplementedError, "Unexpected partial read from random device: only #{ret.length} for #{n} bytes"
      end
      ret
    end

    begin
      # Check if Random.urandom is available
      Random.urandom(1)
      alias gen_random gen_random_urandom
    rescue RuntimeError
      begin
        require 'openssl'
      rescue NoMethodError
        raise NotImplementedError, "No random device"
      else
        alias gen_random gen_random_openssl
      end
    end

    # :startdoc:

    # Generate random data bytes for Random::Formatter
    public :gen_random
  end

  module Formatter
    include Random::Formatter

    # SecureRandom.base64 generates a random base64 string.
    #
    # The argument _n_ specifies the length, in bytes, of the random number
    # to be generated. The length of the result string is about 4/3 of _n_.
    #
    # If _n_ is not specified or is nil, 16 is assumed.
    # It may be larger in the future.
    #
    # The result may contain A-Z, a-z, 0-9, "+", "/" and "=".
    #
    #   require 'securerandom'
    #
    #   SecureRandom.base64 #=> "/2BuBuLf3+WfSKyQbRcc/A=="
    #   SecureRandom.base64 #=> "6BbW0pxO0YENxn38HMUbcQ=="
    #
    # If a secure random number generator is not available,
    # +NotImplementedError+ is raised.
    #
    # See RFC 3548 for the definition of base64.
    def base64(n=nil)
      [random_bytes(n)].pack("m0")
    end

    # SecureRandom.urlsafe_base64 generates a random URL-safe base64 string.
    #
    # The argument _n_ specifies the length, in bytes, of the random number
    # to be generated. The length of the result string is about 4/3 of _n_.
    #
    # If _n_ is not specified or is nil, 16 is assumed.
    # It may be larger in the future.
    #
    # The boolean argument _padding_ specifies the padding.
    # If it is false or nil, padding is not generated.
    # Otherwise padding is generated.
    # By default, padding is not generated because "=" may be used as a URL delimiter.
    #
    # The result may contain A-Z, a-z, 0-9, "-" and "_".
    # "=" is also used if _padding_ is true.
    #
    #   require 'securerandom'
    #
    #   SecureRandom.urlsafe_base64 #=> "b4GOKm4pOYU_-BOXcrUGDg"
    #   SecureRandom.urlsafe_base64 #=> "UZLdOkzop70Ddx-IJR0ABg"
    #
    #   SecureRandom.urlsafe_base64(nil, true) #=> "i0XQ-7gglIsHGV2_BNPrdQ=="
    #   SecureRandom.urlsafe_base64(nil, true) #=> "-M8rLhr7JEpJlqFGUMmOxg=="
    #
    # If a secure random number generator is not available,
    # +NotImplementedError+ is raised.
    #
    # See RFC 3548 for the definition of URL-safe base64.
    def urlsafe_base64(n=nil, padding=false)
      s = [random_bytes(n)].pack("m0")
      s.tr!("+/", "-_")
      s.delete!("=") unless padding
      s
    end
  end

  extend(Formatter)
end
