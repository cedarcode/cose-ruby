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
      LABEL_DP = -6
      LABEL_DQ = -7
      LABEL_QINV = -8

      KTY_RSA = 3

      def self.enforce_type(map)
        if map[LABEL_KTY] != KTY_RSA
          raise "Not an RSA key"
        end
      end

      def self.from_pkey(pkey)
        params = pkey.params

        attributes = {
          n: params["n"].to_s(2),
          e: params["e"].to_s(2)
        }

        if pkey.private?
          attributes.merge!(
            d: params["d"].to_s(2),
            p: params["p"].to_s(2),
            q: params["q"].to_s(2),
            dp: params["dmp1"].to_s(2),
            dq: params["dmq1"].to_s(2),
            qinv: params["iqmp"].to_s(2)
          )
        end

        new(**attributes)
      end

      attr_reader :n, :e, :d, :p, :q, :dp, :dq, :qinv

      def initialize(n:, e:, d: nil, p: nil, q: nil, dp: nil, dq: nil, qinv: nil, **keyword_arguments) # rubocop:disable Naming/MethodParameterName
        super(**keyword_arguments)

        if !n
          raise ArgumentError, "Required public field n is missing"
        elsif !e
          raise ArgumentError, "Required public field e is missing"
        else
          private_fields = { d: d, p: p, q: q, dp: dp, dq: dq, qinv: qinv }

          if private_fields.values.all?(&:nil?) || private_fields.values.none?(&:nil?)
            @n = n
            @e = e
            @d = d
            @p = p
            @q = q
            @dp = dp
            @dq = dq
            @qinv = qinv
          else
            missing = private_fields.detect { |_k, v| v.nil? }[0]
            raise ArgumentError, "Incomplete private fields, #{missing} is missing"
          end
        end
      end

      def map
        super.merge(
          Base::LABEL_KTY => KTY_RSA,
          LABEL_N => n,
          LABEL_E => e,
          LABEL_D => d,
          LABEL_P => p,
          LABEL_Q => q,
          LABEL_DP => dp,
          LABEL_DQ => dq,
          LABEL_QINV => qinv
        ).compact
      end

      def to_pkey
        # PKCS#1 RSAPublicKey
        asn1 = OpenSSL::ASN1::Sequence(
          [
            OpenSSL::ASN1::Integer.new(bn(n)),
            OpenSSL::ASN1::Integer.new(bn(e)),
          ]
        )
        pkey = OpenSSL::PKey::RSA.new(asn1.to_der)

        if private?
          # PKCS#1 RSAPrivateKey
          asn1 = OpenSSL::ASN1::Sequence(
            [
              OpenSSL::ASN1::Integer.new(0),
              OpenSSL::ASN1::Integer.new(bn(n)),
              OpenSSL::ASN1::Integer.new(bn(e)),
              OpenSSL::ASN1::Integer.new(bn(d)),
              OpenSSL::ASN1::Integer.new(bn(p)),
              OpenSSL::ASN1::Integer.new(bn(q)),
              OpenSSL::ASN1::Integer.new(bn(dp)),
              OpenSSL::ASN1::Integer.new(bn(dq)),
              OpenSSL::ASN1::Integer.new(bn(qinv)),
            ]
          )

          pkey = OpenSSL::PKey::RSA.new(asn1.to_der)
        end

        pkey
      end

      def self.keyword_arguments_for_initialize(map)
        {
          n: map[LABEL_N],
          e: map[LABEL_E],
          d: map[LABEL_D],
          p: map[LABEL_P],
          q: map[LABEL_Q],
          dp: map[LABEL_DP],
          dq: map[LABEL_DQ],
          qinv: map[LABEL_QINV]
        }
      end

      private

      def private?
        [d, p, q, dp, dq, qinv].none?(&:nil?)
      end

      def bn(data)
        if data
          OpenSSL::BN.new(data, 2)
        end
      end
    end
  end
end
