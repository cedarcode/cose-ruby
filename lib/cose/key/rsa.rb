# frozen_string_literal: true

require "cose/key/base"
require "openssl"

module COSE
  module Key
    class RSA < Base
      LABEL_N = -1
      LABEL_E = -2
      LABEL_D = -3
      LABEL_P = -4
      LABEL_Q = -5
      LABEL_D_P = -6
      LABEL_D_Q = -7
      LABEL_Q_INV = -8

      KTY_RSA = 3

      def self.from_pkey(pkey)
        params = pkey.params

        attributes = {
          modulus_n: params["n"].to_s(2),
          public_exponent_e: params["e"].to_s(2)
        }

        if pkey.private?
          attributes.merge!(
            private_exponent_d: params["d"].to_s(2),
            prime_factor_p: params["p"].to_s(2),
            prime_factor_q: params["q"].to_s(2),
            d_p: params["dmp1"].to_s(2),
            d_q: params["dmq1"].to_s(2),
            q_inv: params["iqmp"].to_s(2)
          )
        end

        new(attributes)
      end

      attr_reader(
        :modulus_n,
        :public_exponent_e,
        :private_exponent_d,
        :prime_factor_p,
        :prime_factor_q,
        :d_p,
        :d_q,
        :q_inv
      )

      def initialize(
        modulus_n:,
        public_exponent_e:,
        private_exponent_d: nil,
        prime_factor_p: nil,
        prime_factor_q: nil,
        d_p: nil,
        d_q: nil,
        q_inv: nil,
        **keyword_arguments
      )
        super(**keyword_arguments)

        if !modulus_n
          raise ArgumentError, "Required modulus_n is missing"
        elsif !public_exponent_e
          raise ArgumentError, "Required public_exponent_e is missing"
        else
          @modulus_n = modulus_n
          @public_exponent_e = public_exponent_e
          @private_exponent_d = private_exponent_d
          @prime_factor_p = prime_factor_p
          @prime_factor_q = prime_factor_q
          @d_p = d_p
          @d_q = d_q
          @q_inv = q_inv
        end
      end

      def map
        super.merge(
          Base::LABEL_KTY => KTY_RSA,
          LABEL_N => modulus_n,
          LABEL_E => public_exponent_e,
          LABEL_D => private_exponent_d,
          LABEL_P => prime_factor_p,
          LABEL_Q => prime_factor_q,
          LABEL_D_P => d_p,
          LABEL_D_Q => d_q,
          LABEL_Q_INV => q_inv
        )
      end

      def to_pkey
        pkey = OpenSSL::PKey::RSA.new

        if pkey.respond_to?(:set_key)
          pkey.set_key(bn(modulus_n), bn(public_exponent_e), bn(private_exponent_d))
        else
          pkey.n = bn(modulus_n)
          pkey.e = bn(public_exponent_e)
          pkey.d = bn(private_exponent_d)
        end

        if pkey.respond_to?(:set_factors)
          pkey.set_factors(bn(prime_factor_p), bn(prime_factor_q))
        else
          pkey.p = bn(prime_factor_p)
          pkey.q = bn(prime_factor_q)
        end

        if pkey.respond_to?(:set_crt_params)
          pkey.set_crt_params(bn(d_p), bn(d_q), bn(q_inv))
        else
          pkey.dmp1 = bn(d_p)
          pkey.dmq1 = bn(d_q)
          pkey.iqmp = bn(q_inv)
        end

        pkey
      end

      def self.keyword_arguments_for_initialize(map)
        enforce_type(map, KTY_RSA, "Not an RSA key")

        {
          modulus_n: map[LABEL_N],
          public_exponent_e: map[LABEL_E]
        }
      end

      private

      def bn(data)
        OpenSSL::BN.new(data, 2)
      end
    end
  end
end
