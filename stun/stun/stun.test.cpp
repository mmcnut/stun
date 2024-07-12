#include <gtest/gtest.h>

#include <bitset>

#include "message.hpp"

// TEST(STUNMESSAGE, STUNMESSAGETYPE) {
//   // Given a stun message type.
//   auto sm_class = stunmsg::StunMessageClass::INDICATION;
//   auto sm_method = stunmsg::StunMethod::BINDING;
//   stunmsg::StunMessageType stun_message_to_bytes(sm_class, sm_method);
//   std::vector<std::byte> input_vector(2, std::byte{0});

//   // When serializing the packets to bytes.
//   auto input_iter = input_vector.begin();
//   stun_message_to_bytes.ToBytes(input_iter);

//   // Then the unserialized packet should be equivalent.
//   input_iter = input_vector.begin();
//   stunmsg::StunMessageType stun_message_from_bytes(input_iter,
//                                                    input_vector.end());
//   ASSERT_EQ(stun_message_to_bytes, stun_message_from_bytes);
// }

TEST(STUNMESSAGE, STUNMESSAGE) {
  // Given a StunMessage constructed with non-zero fields
  auto sm_class = stunmsg::StunMessageClass::INDICATION;
  auto sm_method = stunmsg::StunMethod::BINDING;
  std::array<std::byte, 12> transaction_id;
  transaction_id.fill(std::byte{12});
  stunmsg::StunMessage stun_message_in(sm_class, sm_method);
  stun_message_in.SetMessageLength(20);
  stun_message_in.SetTransactionId(transaction_id);

  // When serializing the packet to bytes
  std::vector<std::byte> input_vector(120, std::byte{0});
  auto input_iter = input_vector.begin();
  stun_message_in.ToBytes(input_iter, input_vector.end());

  // Then constructing a StunMessage from bytes should result in the same obj.
  stunmsg::StunMessage stun_message_out;
  input_iter = input_vector.begin();
  stun_message_out.FromBytes(input_iter, input_vector.end());

  ASSERT_EQ(stun_message_in, stun_message_out);
}
