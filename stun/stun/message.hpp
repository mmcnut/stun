#include <bitset>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace stunmsg {

unsigned char BYTE_MASK = 0xFF;

unsigned char SHIFT_ONE_BYTES = 8;
unsigned char SHIFT_TWO_BYTES = 16;
unsigned char SHIFT_THREE_BYTES = 24;

int MESSAGE_TYPE_SIZE = 2;
uint32_t MAGIC_COOKIE = 0x2112A442;

/**
 * @brief Enumeration with all possible STUN message classes
 */
enum class StunMessageClass {
  REQUEST = 0,
  INDICATION,
  SUCCESS_RESPONSE,
  ERROR_RESPONSE
};

/**
 * Enumeration with all possible STUN methods
 */
enum class StunMethod { BINDING = 1 };

enum class AttributeTypes {
  // Comprehension-required range (0x0000-0x7FFF)
  MAPPED_ADDRESS = 0x0001,
  USERNAME = 0x0006,
  MESSAGE_INTEGRITY = 0x0008,
  ERROR_CODE,
  UNKNOWN_ATTRIBUTES,
  REALM = 0x0014,
  NONCE,
  XOR_MAPPED_ADDRESS = 0x0020,

  // Comprehension-optional range (0x8000-0xFFFF)
  SOFTWARE = 0x8022,
  ALTERNATE_SERVER,
  FINGERPRINT = 0x8028
};

enum class AddressFamilies { IPv4 = 1, IPv6 = 2 };

class StunAttribute {
 public:
  StunAttribute(AttributeTypes type, uint16_t length)
      : type_(type), length_(length){};

  virtual void ToBytes(std::vector<std::byte>::iterator& begin,
                       const std::vector<std::byte>::iterator end) = 0;

  virtual void FromBytes() = 0;

  void SetLength(uint16_t length) { length_ = length; }

 protected:
  void StunAttributeHeaderToBytes(std::vector<std::byte>::iterator& begin,
                                  const std::vector<std::byte>::iterator end) {
    *begin++ = std::byte{(static_cast<int>(type_) >> 8) & BYTE_MASK};
    *begin++ = std::byte{static_cast<int>(type_) & BYTE_MASK};
    *begin++ = std::byte{length_ >> 8 & BYTE_MASK};
    *begin++ = std::byte{length_ & BYTE_MASK};
  }

 private:
  AttributeTypes type_;
  uint16_t length_;
};

class MappedAddress : public StunAttribute {
 public:
  MappedAddress(u_int16_t port, std::string address, AddressFamilies family,
                AttributeTypes type)
      : port_(port),
        family_(family),
        StunAttribute(AttributeTypes::MAPPED_ADDRESS, 4) {
    int octet_1, octet_2, octet_3, octet_4;
    sscanf(address, '%d.%d.%d.%d', &octet_1, &octet_2, &octet_3, &octet_4);
    address_ += (octet_1 << 24) + (octet_2 << 16) + (octet_3 << 8) + octet_4;
  };

  void ToBytes(std::vector<std::byte>::iterator& begin,
               const std::vector<std::byte>::iterator end) override {
    StunAttributeHeaderToBytes(begin, begin + 4);
    *begin++ = std::byte{0};
    *begin++ = std::byte{static_cast<int>(family_)};
    *begin++ = std::byte{(port_ >> 8) & BYTE_MASK};
    *begin++ = std::byte{port_ & BYTE_MASK};
  }

  void FromBytes() override {}

 private:
  uint16_t port_;
  uint32_t address_;
  AddressFamilies family_;
};

class TypeLengthValueHeader {
 public:
  TypeLengthValueHeader() = default;

 private:
  AttributeTypes type_;
  uint16_t length_;
};

/**
 * @brief Class to manage the slight complexity of the STUN message type field
 * along with leading zeros
 */
class StunMessageType {
 public:
  StunMessageType() = default;

  StunMessageType(StunMessageClass sm_class, StunMethod sm_method)
      : class_(sm_class), method_(sm_method) {}

  StunMessageType(std::vector<std::byte>::iterator& begin,
                  const std::vector<std::byte>::iterator& end) {
    FromBytes(begin, end);
  }

  void ToBytes(std::vector<std::byte>::iterator& begin,
               const std::vector<std::byte>::iterator end) {
    if (std::distance(begin, end) == 2) {
      // The first byte is currently just the
      *(begin++) = std::byte{static_cast<int>(class_) & 0x02};
      *(begin++) = std::byte{(static_cast<int>(class_) & 0x01) << 4};
    }
  }

  void FromBytes(std::vector<std::byte>::iterator& begin,
                 std::vector<std::byte>::iterator end) {
    int from_class = 0;

    // Verify there is enough room for the StunMessageType
    if (std::distance(begin, end) == 2) {
      from_class += static_cast<int>((*begin++) << 1);
      from_class += ((static_cast<int>(*begin++) >> 4) & 0x1);

      // TODO - StunMethod is hard coded until I know if there are more methods.
      class_ = StunMessageClass(from_class);
      method_ = StunMethod::BINDING;
    } else {
      throw std::length_error("Supplied with incorrect number of bytes.");
    }
  }

  const bool operator==(const StunMessageType& rhs) const {
    return (this->class_ == rhs.class_ && this->method_ == rhs.method_);
  }

 private:
  StunMessageClass class_;
  StunMethod method_;
};

/**
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0|     STUN Message Type     |         Message Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         Magic Cookie                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                     Transaction ID (96 bits)                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
class StunMessage {
 public:
  /**
   * Constructor designed to be used when no attributes of the message are
   * known. Typically used when bytes are received.
   */
  StunMessage() : stun_message_type_() { transaction_id_.fill(std::byte{0}); }

  /**
   * Constructor designed to be used when the primary attributes of the STUN
   * message are known. Typically in the case that it will be sent to another
   * STUN node.
   */
  StunMessage(StunMessageClass sm_class, StunMethod sm_method)
      : stun_message_type_(sm_class, sm_method) {
    transaction_id_.fill(std::byte{0});
  };

  /**
   * Method to convert a STUN object to serialized bits/bytes.
   *
   * @param begin should be an iterator to a location in a container where the
   * caller would like to start to serialize the STUN packet. The iterator will
   * be incremented based on the number of bytes written.
   *
   * @param end The location where the user would like to stop serializing
   * the packet. If the distance between begin & end isn't long enough to hold
   * the packet an exception will be thrown.
   *
   * @throws std::length_error if the buffer doesn't have enough space to hold
   * the packet.
   */
  void ToBytes(std::vector<std::byte>::iterator& begin,
               const std::vector<std::byte>::iterator end) {
    stun_message_type_.ToBytes(begin, begin + 2);
    MessageLengthToBytes(begin, begin + 2);
    MagicCookieToBytes(begin, begin + 4);
    TransactionIdToBytes(begin, begin + 12);
  }

  /**
   * Method to take serialized bytes and convert them into a STUN object.
   *
   * @param begin should be an iterator to the location in the container where
   * the STUN object begins. The iterator will be iterated based on the number
   * of bytes written.
   *
   * @param end should be an iterator to the end location of the STUN message.
   *
   */
  void FromBytes(std::vector<std::byte>::iterator& begin,
                 const std::vector<std::byte>::iterator end) {
    stun_message_type_.FromBytes(begin, begin + 2);
    MessageLengthFromBytes(begin, begin + 2);
    MagicCookieFromBytes(begin, begin + 4);
    TransactionIdFromBytes(begin, begin + 12);
  }

  /**
   * Setter for the total message length. This should follow the definition set
   * in the RFC.
   */
  void SetMessageLength(int message_length) {
    message_length_ = message_length;
  }

  /**
   * Setter for the transaction ID. It should follow the definition set in the
   * RFC.
   */
  void SetTransactionId(std::array<std::byte, 12> value) {
    std::memcpy(static_cast<void*>(&transaction_id_),
                static_cast<void*>(&value), 12);
  }

  const bool operator==(const StunMessage& rhs) const {
    if (stun_message_type_ == rhs.stun_message_type_ &&
        message_length_ == rhs.message_length_ &&
        magic_cookie_ == rhs.magic_cookie_ &&
        transaction_id_ == rhs.transaction_id_) {
      return true;
    } else {
      return false;
    }
  }

 private:
  void MessageLengthToBytes(std::vector<std::byte>::iterator& begin,
                            const std::vector<std::byte>::iterator end) {
    if (std::distance(begin, end) == 2) {
      (*begin++) = std::byte{message_length_ >> SHIFT_ONE_BYTES};
      (*begin++) = std::byte{message_length_ & BYTE_MASK};
    }
  }

  void MessageLengthFromBytes(std::vector<std::byte>::iterator& begin,
                              const std::vector<std::byte>::iterator end) {
    message_length_ = 0;
    if (std::distance(begin, end) == 2) {
      message_length_ += static_cast<int>(*begin++) << SHIFT_ONE_BYTES;
      message_length_ += static_cast<int>(*begin++) & 0xFF;
    } else {
      throw std::length_error("Supplied with incorrect number of bytes.");
    }
  }

  void MagicCookieToBytes(std::vector<std::byte>::iterator& begin,
                          const std::vector<std::byte>::iterator end) {
    magic_cookie_ = MAGIC_COOKIE;
    if (std::distance(begin, end) == 4) {
      (*begin++) = std::byte{(magic_cookie_ >> SHIFT_THREE_BYTES) & BYTE_MASK};
      (*begin++) = std::byte{(magic_cookie_ >> SHIFT_TWO_BYTES) & BYTE_MASK};
      (*begin++) = std::byte{(magic_cookie_ >> SHIFT_ONE_BYTES) & BYTE_MASK};
      (*begin++) = std::byte{magic_cookie_ & BYTE_MASK};
    } else {
      throw std::length_error("Supplied with incorrect number of bytes.");
    }
  }

  void MagicCookieFromBytes(std::vector<std::byte>::iterator& begin,
                            const std::vector<std::byte>::iterator end) {
    magic_cookie_ = 0;
    if (std::distance(begin, end) == 4) {
      magic_cookie_ += static_cast<uint32_t>(*begin++) << 24;
      magic_cookie_ += static_cast<uint32_t>(*begin++) << 16;
      magic_cookie_ += static_cast<uint32_t>(*begin++) << 8;
      magic_cookie_ += static_cast<uint32_t>(*begin++);
    } else {
      throw std::length_error("Supplied with incorrect number of bytes.");
    }

    if (magic_cookie_ != MAGIC_COOKIE) {
      throw std::domain_error(
          "Magic cookie constructed from bytes is incorrect.");
    }
  }

  void TransactionIdToBytes(std::vector<std::byte>::iterator& begin,
                            const std::vector<std::byte>::iterator end) {
    if (std::distance(begin, end) == 12) {
      std::memcpy(static_cast<void*>(&(*begin)),
                  static_cast<void*>(&transaction_id_),
                  std::distance(begin, end));
    } else {
      throw std::length_error("Supplied with incorrect number of bytes.");
    }
  }

  void TransactionIdFromBytes(std::vector<std::byte>::iterator& begin,
                              const std::vector<std::byte>::iterator end) {
    if (std::distance(begin, end) == 12) {
      std::memcpy(static_cast<void*>(&transaction_id_),
                  static_cast<void*>(&(*begin)), std::distance(begin, end));
    }
  }

  int header_length_ = 158;
  uint32_t magic_cookie_ = MAGIC_COOKIE;
  StunMessageType stun_message_type_;
  int message_length_ = 0;
  std::array<std::byte, 12> transaction_id_;
};
};  // namespace stunmsg