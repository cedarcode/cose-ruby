# frozen_string_literal: true

module COSE
  module Algorithm
    class Base
      BYTE_LENGTH = 8

      attr_reader :id, :name

      def initialize(id, name)
        @id = id
        @name = name
      end
    end
  end
end
