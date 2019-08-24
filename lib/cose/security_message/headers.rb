# frozen_string_literal: true

module COSE
  class SecurityMessage
    class Headers
      HEADER_LABEL_ALG = 1
      HEADER_LABEL_KID = 4

      attr_reader :protected_bucket, :unprotected_bucket

      def initialize(protected_bucket, unprotected_bucket)
        @protected_bucket = protected_bucket
        @unprotected_bucket = unprotected_bucket
      end

      def alg
        header(HEADER_LABEL_ALG)
      end

      def kid
        header(HEADER_LABEL_KID)
      end

      private

      def header(label)
        protected_bucket[label] || unprotected_bucket[label]
      end
    end
  end
end
