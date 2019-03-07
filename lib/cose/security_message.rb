module COSE
  class SecurityMessage
    attr_reader :protected_headers, :unprotected_headers

    def initialize(protected_headers:, unprotected_headers:)
      @protected_headers = protected_headers
      @unprotected_headers = unprotected_headers
    end
  end
end
