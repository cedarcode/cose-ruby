# frozen_string_literal: true

require "cose/algorithm/base"
require "openssl"

module COSE
  module Algorithm
    class HMAC < Base
      BYTE_LENGTH = 8

      attr_reader :hash_function, :tag_length

      def initialize(*args, hash_function:, tag_length:)
        super(*args)

        @hash_function = hash_function
        @tag_length = tag_length
      end

      def mac(key, to_be_signed)
        mac = OpenSSL::HMAC.digest(hash_function, key, to_be_signed)

        if tag_bytesize && tag_bytesize < mac.bytesize
          mac.byteslice(0, tag_bytesize)
        else
          mac
        end
      end

      private

      def tag_bytesize
        @tag_bytesize ||=
          if tag_length
            tag_length / BYTE_LENGTH
          end
      end
    end
  end
end
