#include "../../include/pkg/client.hpp"

#include <sys/ioctl.h>

#include <boost/asio.hpp>
#include <boost/lexical_cast.hpp>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

#include "../../include-shared/util.hpp"
#include "colors.hpp"

/**
 * Constructor. Sets up TCP socket and starts REPL
 * @param command One of "listen" or "connect"
 * @param address Address to listen on or connect to.q
 * @param port Port to listen on or connect to.
 */
Client::Client(std::shared_ptr<NetworkDriver> network_driver,
               std::shared_ptr<CryptoDriver> crypto_driver) {
  // Make shared variables.
  this->cli_driver = std::make_shared<CLIDriver>();
  this->crypto_driver = crypto_driver;
  this->network_driver = network_driver;
}

/**
 * Generates a new DH secret and replaces the keys. This function should:
 * 1) Call DH_generate_shared_key
 * 2) Use the resulting key in AES_generate_key and HMAC_generate_key
 * 3) Update private key variables
 */
void Client::prepare_keys(CryptoPP::SecByteBlock shared_key,
                          CryptoPP::SecByteBlock chain_key) {
  // TODO: implement me!
  auto [new_chain_key, sym_key] = this->crypto_driver->rachet_key(shared_key, chain_key);
  this->AES_key = crypto_driver->AES_generate_key(shared_key, sym_key);
  this->HMAC_key = crypto_driver->HMAC_generate_key(shared_key, sym_key);
  this->chain_key = new_chain_key;
}

void Client::DH_change(CryptoPP::DH DH_obj,
                       CryptoPP::SecByteBlock DH_private_value,
                       CryptoPP::SecByteBlock DH_other_public_value,
                       CryptoPP::SecByteBlock root_key, bool recompute) {
  SecByteBlock shared_key = crypto_driver->DH_generate_shared_key(DH_obj, DH_private_value, DH_other_public_value);;
  if(!recompute){
    this->DH_old_private_values.push_back(DH_private_value);
    this->DH_old_public_values.push_back(DH_other_public_value);
  }
  auto [new_root_key, chain_key] = this->crypto_driver->rachet_key(shared_key, root_key);
  prepare_keys(shared_key, chain_key);
  this->root_key = new_root_key;
  this->shared_key = shared_key;
}

void Client::Out_of_Order_key(CryptoPP::Integer thread_num, CryptoPP::Integer msg_num) {
  for(int thread = 1; thread <= thread_num; thread++) {
    if(thread >= this->DH_old_private_values.size()){
      DH_change(this->dh, this->DH_current_private_value, this->DH_last_other_public_value, this->base_key, false);
    } else {
      DH_change(this->dh, this->DH_old_private_values.at(thread), this->DH_old_public_values.at(thread), this->base_key, true);
    }
  }
  for(int msg = 1; msg <= msg_num; msg++){
    prepare_keys(this->shared_key, this->chain_key);
  }
}

/**
 * Encrypts the given message and returns a Message struct. This function
 * should:
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Encrypt and tag the message.
 */
Message_Message Client::send(std::string plaintext) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);

  // TODO: implement me!
  // Switching the DH Ratchet keys
  if (this->DH_switched) {
    auto dh_keys = crypto_driver->DH_initialize(this->DH_params);
    this->DH_current_private_value = std::get<1>(dh_keys);
    this->DH_current_public_value = std::get<2>(dh_keys);
    this->DH_switched = false;
    DH_change(this->dh, this->DH_current_private_value, this->DH_last_other_public_value, this->root_key, false);
    this->cur_thread_num += 1;
    this->cur_msg_num = 0;
  } else { // If not then rachet sending keys to next value
    prepare_keys(this->shared_key, this->chain_key);
    this->cur_msg_num += 1;
  }

  // Encrypting and generating the mac
  auto [ciphertext, iv] = crypto_driver->AES_encrypt(this->AES_key, plaintext);
  std::string hmac_text =  concat_msg_fields(iv, this->DH_current_public_value, ciphertext);
  std::string mac = crypto_driver->HMAC_generate(this->HMAC_key, hmac_text);

  // Creating the message
  Message_Message msg;
  msg.thread_num = this->cur_thread_num;
  msg.message_num = this->cur_msg_num;
  msg.public_value = this->DH_current_public_value;
  msg.iv = iv;
  msg.ciphertext = ciphertext;
  msg.mac = mac;
  
  return msg;

}

/**
 * Decrypts the given Message into a tuple containing the plaintext and
 * an indicator if the MAC was valid (true if valid; false otherwise).
 * 1) Check if the DH Ratchet keys need to change; if so, update them.
 * 2) Decrypt and verify the message.
 */
std::pair<std::string, bool> Client::receive(Message_Message msg) {
  // Grab the lock to avoid race conditions between the receive and send threads
  // Lock will automatically release at the end of the function.
  std::unique_lock<std::mutex> lck(this->mtx);

  // TODO: implement me!
  bool reset_key = false;
  // std::cout << msg.thread_num << ", " << msg.message_num << "\n";
  // Adjusting keys
  if (this->cur_thread_num != msg.thread_num || this->cur_msg_num+1 != msg.message_num) {
    // Rachet the root key foward if a new public value was received
    if (msg.thread_num > this->cur_thread_num) {
      this->DH_switched = true;
      DH_change(this->dh, this->DH_current_private_value, msg.public_value, this->root_key, false);
      this->DH_last_other_public_value = msg.public_value;
      this->cur_thread_num = msg.thread_num;
      this->cur_msg_num = msg.message_num;
      if(msg.message_num != 0) {
        Out_of_Order_key(msg.thread_num, msg.message_num);
      }
    } else { // an out of order previous message was recieced 
      reset_key = true;
      Out_of_Order_key(msg.thread_num, msg.message_num);
      if(msg.thread_num > this->cur_msg_num){
        this->cur_msg_num = msg.message_num;
      }
    }
  } else { // If not then rachet receiving keys to next value
    prepare_keys(this->shared_key, this->chain_key);
    this->cur_msg_num = msg.message_num;
  }
  std::string hmac_text = concat_msg_fields(msg.iv, msg.public_value, msg.ciphertext);
  bool verify = crypto_driver->HMAC_verify(this->HMAC_key, hmac_text, msg.mac);
  
  // Simply return and dont bother decrypting if HMAC failed
  if (!verify){
    return std::pair<std::string, bool>("", verify);
  }

  std::string plaintext = crypto_driver->AES_decrypt(this->AES_key, msg.iv, msg.ciphertext);

  if (reset_key) {
    Out_of_Order_key(this->cur_thread_num, this->cur_msg_num);
  }
  return  std::pair<std::string, bool>(plaintext, verify);

}

/**
 * Run the client.
 */
void Client::run(std::string command) {
  // Initialize cli_driver.
  this->cli_driver->init();

  // Run key exchange.
  this->HandleKeyExchange(command);

  // Start msgListener thread.
  boost::thread msgListener =
      boost::thread(boost::bind(&Client::ReceiveThread, this));
  msgListener.detach();

  // Start sending thread.
  this->SendThread();
}

/**
 * Run key exchange. This function:
 * 1) Listen for or generate and send DHParams_Message depending on `command`
 * `command` can be either "listen" or "connect"; the listener should read()
 * for params, and the connector should generate and send params.
 * 2) Initialize DH object and keys
 * 3) Send your public value
 * 4) Listen for the other party's public value
 * 5) Generate DH, AES, and HMAC keys and set local variables
 */
void Client::HandleKeyExchange(std::string command) {
  // TODO: implement me!
  DHParams_Message params_msg;
  // Send or recieve the Diffie Helm key message.
  if (command == "listen"){
    std::vector<unsigned char> data = this->network_driver->read();
    params_msg.deserialize(data);

  } else {
    params_msg = this->crypto_driver->DH_generate_params();
    std::vector<unsigned char> data;
    params_msg.serialize(data);
    this->network_driver->send(data, false);
  }

  // Generate private and public keys
  std::tuple<DH, SecByteBlock, SecByteBlock> DH_keys = this->crypto_driver->DH_initialize(params_msg);
  PublicValue_Message public_msg;
  public_msg.public_value = std::get<2>(DH_keys);
  // Sending the public key
  std::vector<unsigned char> data;
  public_msg.serialize(data);
  this->network_driver->send(data, false);
  // Receiving the other client's public key
  data = this->network_driver->read();
  PublicValue_Message rec_public_msg;
  rec_public_msg.deserialize(data);

  // Generate keys
  std::string salt_str("salt0000");
  SecByteBlock salt((const unsigned char *)(salt_str.data()), salt_str.size());
  DH_change(std::get<0>(DH_keys), std::get<1>(DH_keys), rec_public_msg.public_value, salt, false);
  

  // Save Keys
  this->base_key = this->root_key;
  this->DH_current_private_value = std::get<1>(DH_keys);
  this->DH_current_public_value = std::get<2>(DH_keys);
  this->DH_last_other_public_value = rec_public_msg.public_value;
  this->DH_params = params_msg;
  this->dh = std::get<0>(DH_keys);
  this->cur_thread_num = 0;
  this->cur_msg_num = 0;
  this->DH_switched = true;
}

/**
 * Listen for messages and print to cli_driver.
 */
void Client::ReceiveThread() {
  while (true) {
    // Try reading data from the other user.
    std::vector<unsigned char> data;
    try {
      data = this->network_driver->read();
    } catch (std::runtime_error &_) {
      // Exit cleanly.
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Deserialize, decrypt, and verify message.
    Message_Message msg;
    msg.deserialize(data);
    auto decrypted_data = this->receive(msg);
    if (!decrypted_data.second) {
      this->cli_driver->print_left("Received invalid HMAC; the following "
                                   "message may have been tampered with.");
      throw std::runtime_error("Received invalid MAC!");
    }
    this->cli_driver->print_left(std::get<0>(decrypted_data));
  }
}

/**
 * Listen for stdin and send to other party.
 */
void Client::SendThread() {
  std::string plaintext;
  while (true) {
    // Read from STDIN.
    std::getline(std::cin, plaintext);
    if (std::cin.eof()) {
      this->cli_driver->print_left("Received EOF; closing connection");
      this->network_driver->disconnect();
      return;
    }

    // Encrypt and send message.
    if (plaintext != "") {
      Message_Message msg = this->send(plaintext);
      std::vector<unsigned char> data;
      msg.serialize(data);
      this->network_driver->send(data, true);
    }
    this->cli_driver->print_right(plaintext);
  }
}
