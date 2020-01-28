# frozen_string_literal: true

module COSE
  module Algorithm
    class Base
      attr_reader :id, :name

      def initialize(id, name)
        @id = id
        @name = name
      end
    end
  end
end
