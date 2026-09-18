# frozen_string_literal: true

module COSE
  module Key
    # Shared by COSE::Key::EC2 (public key coordinates) and COSE::Algorithm::ECDSA (signature
    # r/s values): RFC 8152 requires both to be left-padded with zero bytes to a fixed,
    # curve-dependent length.
    module CoordinatePadding
      module_function

      def pad_coordinate(coordinate, length)
        padding_required = length - coordinate.bytesize
        return coordinate if padding_required <= 0

        ("\x00".b * padding_required) + coordinate
      end
    end
  end
end
