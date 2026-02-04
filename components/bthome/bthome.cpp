#include "bthome.h"
#include "esphome/core/log.h"
#include "esphome/core/version.h"

#if defined(USE_ESP32) || defined(USE_NRF52)

#include <cstring>
#include <cmath>

// Platform-specific includes
#ifdef USE_ESP32
  #ifdef USE_BTHOME_NIMBLE
    #include "nimble/nimble_port.h"
    #include "nimble/nimble_port_freertos.h"
    #include "host/ble_hs.h"
    #include "host/util/util.h"
    #include <esp_bt.h>
    #include <nvs_flash.h>
    // NimBLE uses tinycrypt for encryption
    #include "tinycrypt/ccm_mode.h"
    #include "tinycrypt/constants.h"
  #else
    #include <esp_bt_device.h>
    #include <esp_bt_main.h>
    #include <esp_gap_ble_api.h>
    #include "esphome/core/hal.h"
    #include "mbedtls/ccm.h"
  #endif
#endif

#ifdef USE_NRF52
#include <zephyr/kernel.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/constants.h>
#endif

// ======================================================================
// 【核心修改 1/3】定义 RTC 变量，确保 Deep Sleep 数据不丢失
// ======================================================================
#ifdef USE_ESP32
static uint32_t RTC_DATA_ATTR g_bthome_counter = 0;
static uint8_t  RTC_DATA_ATTR g_bthome_packet_id = 0;
#endif
// ======================================================================

namespace esphome {
namespace bthome {

static const char *const TAG = "bthome";

#if defined(USE_ESP32) && defined(USE_BTHOME_NIMBLE)
// Static instance for NimBLE callbacks
BTHome *BTHome::instance_ = nullptr;
#endif

void BTHome::dump_config() {
  ESP_LOGCONFIG(TAG,
                "BTHome:\n"
                "  Min Interval: %ums\n"
                "  Max Interval: %ums\n"
                "  TX Power: %ddBm\n"
                "  Encryption: %s\n"
                "  Retransmit: %dx @ %ums\n"
#if defined(USE_ESP32) && defined(USE_BTHOME_NIMBLE)
                "  BLE Stack: NimBLE",
#elif defined(USE_ESP32)
                "  BLE Stack: Bluedroid",
#else
                "  BLE Stack: Zephyr",
#endif
                this->min_interval_, this->max_interval_,
#ifdef USE_ESP32
                (this->tx_power_esp32_ * 3) - 12,
#else
                this->tx_power_nrf52_,
#endif
                this->encryption_enabled_ ? "enabled" : "disabled",
                this->retransmit_count_, this->retransmit_interval_);
  if (!this->device_name_.empty()) {
    ESP_LOGCONFIG(TAG, "  Device Name: %s", this->device_name_.c_str());
  }
  if (this->has_manufacturer_id_) {
    ESP_LOGCONFIG(TAG, "  Manufacturer ID: 0x%04X", this->manufacturer_id_);
  }
  if (this->trigger_based_) {
    ESP_LOGCONFIG(TAG, "  Trigger-based: yes");
  }
#ifdef USE_SENSOR
  ESP_LOGCONFIG(TAG, "  Sensors: %d", this->measurements_.size());
#endif
#ifdef USE_BINARY_SENSOR
  ESP_LOGCONFIG(TAG, "  Binary Sensors: %d", this->binary_measurements_.size());
#endif
#ifdef USE_EVENT
  ESP_LOGCONFIG(TAG, "  Events: %d", this->event_measurements_.size());
#endif
}

float BTHome::get_setup_priority() const {
#ifdef USE_ESP32
  return setup_priority::AFTER_BLUETOOTH;
#else
  return setup_priority::BLUETOOTH;
#endif
}

void BTHome::setup() {
  ESP_LOGD(TAG, "Setting up BTHome...");

#ifdef USE_ESP32
  // ======================================================================
  // 【核心修改 2/3】从 RTC 恢复并强制自增
  // ======================================================================
  // 必须 +1，否则唤醒后发出的第一个包 Counter 会和上次休眠前一样
  // HA 会认为这是重放攻击而丢弃第一条指令
  this->counter_ = g_bthome_counter + 1;
  
  // Packet ID 也建议跳过一点，防止去重误判
  this->packet_id_ = g_bthome_packet_id + 2; 
  
  ESP_LOGD(TAG, "RTC Restored: Counter=%u, PacketID=%u", this->counter_, this->packet_id_);
  // ======================================================================

  #ifdef USE_BTHOME_NIMBLE
  // NimBLE stack initialization
  instance_ = this;

  // 1. Initialize NVS (required by NimBLE)
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
  }
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "NVS flash init failed: %s", esp_err_to_name(ret));
    this->mark_failed();
    return;
  }

  // 2. Initialize NimBLE
  ret = nimble_port_init();
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "NimBLE port init failed: %s", esp_err_to_name(ret));
    this->mark_failed();
    return;
  }

  // 3. Configure NimBLE host callbacks
  ble_hs_cfg.sync_cb = nimble_on_sync_;
  ble_hs_cfg.reset_cb = nimble_on_reset_;

  // --- 关键修复：先设置初始化标志位，再启动任务 ---
  this->nimble_initialized_ = true;

  // 4. Start NimBLE host task
  nimble_port_freertos_init(nimble_host_task_);

  ESP_LOGD(TAG, "NimBLE initialized, waiting for sync...");

  #else
  // Bluedroid stack initialization
  this->ble_adv_params_ = {
      .adv_int_min = static_cast<uint16_t>(this->min_interval_ / 0.625f),
      .adv_int_max = static_cast<uint16_t>(this->max_interval_ / 0.625f),
      .adv_type = ADV_TYPE_NONCONN_IND,
      .own_addr_type = BLE_ADDR_TYPE_PUBLIC,
      .peer_addr = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
      .peer_addr_type = BLE_ADDR_TYPE_PUBLIC,
      .channel_map = ADV_CHNL_ALL,
      .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
  };

  global_ble->advertising_register_raw_advertisement_callback([this](bool advertise) {
    this->advertising_ = advertise;
    if (advertise) {
      this->build_advertisement_data_();
      this->build_scan_response_data_();
      this->start_advertising_();
    }
  });
  #endif
#endif

#ifdef USE_NRF52
  // nRF52 logic...
  int err = bt_enable(nullptr);
  if (err) {
    ESP_LOGE(TAG, "Bluetooth init failed (err %d)", err);
    this->mark_failed();
    return;
  }
  ESP_LOGD(TAG, "Bluetooth initialized");
  this->adv_param_ = BT_LE_ADV_PARAM_INIT(BT_LE_ADV_OPT_USE_IDENTITY, BT_GAP_ADV_FAST_INT_MIN_2, BT_GAP_ADV_FAST_INT_MAX_2, nullptr);
  this->adv_param_.interval_min = this->min_interval_ * 1000 / 625;
  this->adv_param_.interval_max = this->max_interval_ * 1000 / 625;
#endif

  // Register callbacks for sensor state changes
#ifdef USE_SENSOR
  for (size_t i = 0; i < this->measurements_.size(); i++) {
    auto &measurement = this->measurements_[i];
    measurement.sensor->add_on_state_callback([this, i](float) {
      if (this->measurements_[i].advertise_immediately) {
        this->trigger_immediate_advertising_(i, ImmediateType::SENSOR);
      } else {
        this->data_changed_ = true;
#ifdef USE_ESP32
        this->enable_loop();
#endif
      }
    });
  }
#endif

#ifdef USE_BINARY_SENSOR
  for (size_t i = 0; i < this->binary_measurements_.size(); i++) {
    auto &measurement = this->binary_measurements_[i];
    measurement.sensor->add_on_state_callback([this, i](bool) {
      if (this->binary_measurements_[i].advertise_immediately) {
        this->trigger_immediate_advertising_(i, ImmediateType::BINARY);
      } else {
        this->data_changed_ = true;
#ifdef USE_ESP32
        this->enable_loop();
#endif
      }
    });
  }
#endif

#ifdef USE_EVENT
  for (size_t i = 0; i < this->event_measurements_.size(); i++) {
    auto &measurement = this->event_measurements_[i];
    measurement.event->add_on_event_callback([this, i](const std::string &event_type) {
      uint8_t event_code = 0;
      if (!this->map_button_event_type_(event_type, &event_code)) {
        ESP_LOGW(TAG, "Unknown event type '%s' (ignored)", event_type.c_str());
        return;
      }
      this->queue_button_event_(i, event_code, this->event_measurements_[i].advertise_immediately);
    });
  }
#endif

#ifdef USE_NRF52
  this->build_advertisement_data_();
  this->build_scan_response_data_();
  this->start_advertising_();
#endif

#ifdef USE_ESP32
  this->disable_loop();
#endif
}

void BTHome::loop() {
  uint32_t now = esp_timer_get_time() / 1000;

  if (this->retransmit_remaining_ > 0 && this->advertising_) {
    if (now - this->last_retransmit_time_ >= this->retransmit_interval_) {
      ESP_LOGD(TAG, "Retransmitting (%d remaining)", this->retransmit_remaining_);
      this->retransmit_remaining_--;
      this->last_retransmit_time_ = now;
      this->stop_advertising_();
      this->start_advertising_();
#ifdef USE_ESP32
      if (this->retransmit_remaining_ == 0) {
        this->disable_loop();
      }
#endif
    }
    return;
  }

  if (this->immediate_advertising_pending_) {
    this->stop_advertising_();
    this->build_advertisement_data_();
    this->immediate_advertising_pending_ = false;
    this->immediate_adv_type_ = ImmediateType::NONE;
    this->start_advertising_();
    if (this->retransmit_count_ > 0) {
      this->retransmit_remaining_ = this->retransmit_count_;
      this->last_retransmit_time_ = now;
    } else {
#ifdef USE_ESP32
      this->disable_loop();
#endif
    }
    return;
  }

  if (this->data_changed_ && this->advertising_) {
    this->data_changed_ = false;
    this->stop_advertising_();
    this->build_advertisement_data_();
    this->start_advertising_();
    if (this->retransmit_count_ > 0) {
      this->retransmit_remaining_ = this->retransmit_count_;
      this->last_retransmit_time_ = now;
    } else {
#ifdef USE_ESP32
      this->disable_loop();
#endif
    }
  }
}

void BTHome::set_encryption_key(const std::array<uint8_t, 16> &key) {
  this->encryption_enabled_ = true;
  this->encryption_key_ = key;
}

void BTHome::set_device_name(const std::string &name) {
  if (name.length() > MAX_DEVICE_NAME_LENGTH) {
    this->device_name_ = name.substr(0, MAX_DEVICE_NAME_LENGTH);
    ESP_LOGW(TAG, "Device name truncated to %d characters", MAX_DEVICE_NAME_LENGTH);
  } else {
    this->device_name_ = name;
  }
}

#ifdef USE_SENSOR
void BTHome::add_measurement(sensor::Sensor *sensor, uint8_t object_id, uint8_t data_bytes,
                              bool is_signed, float factor, bool advertise_immediately) {
  this->measurements_.push_back({sensor, object_id, data_bytes, is_signed, factor, advertise_immediately});
}
#endif

#ifdef USE_BINARY_SENSOR
void BTHome::add_binary_measurement(binary_sensor::BinarySensor *sensor, uint8_t object_id, bool advertise_immediately) {
  this->binary_measurements_.push_back({sensor, object_id, advertise_immediately});
}
#endif

#ifdef USE_EVENT
void BTHome::add_event_measurement(event::Event *event, bool advertise_immediately) {
  this->event_measurements_.push_back({event, advertise_immediately});
}
#endif

void BTHome::trigger_immediate_advertising_(uint8_t measurement_index, ImmediateType type) {
  this->immediate_advertising_pending_ = true;
  this->immediate_adv_measurement_index_ = measurement_index;
  this->immediate_adv_type_ = type;
#ifdef USE_ESP32
  this->enable_loop();
#endif
}

void BTHome::build_advertisement_data_() {
  size_t pos = 0;

  this->adv_data_[pos++] = 0x02;
  this->adv_data_[pos++] = 0x01;
  this->adv_data_[pos++] = 0x06;

  size_t service_data_len_pos = pos;
  pos++;
  this->adv_data_[pos++] = 0x16;

  this->adv_data_[pos++] = BTHOME_SERVICE_UUID & 0xFF;
  this->adv_data_[pos++] = (BTHOME_SERVICE_UUID >> 8) & 0xFF;

  uint8_t device_info;
  if (this->trigger_based_) {
    device_info = this->encryption_enabled_ ? BTHOME_DEVICE_INFO_TRIGGER_ENCRYPTED : BTHOME_DEVICE_INFO_TRIGGER_UNENCRYPTED;
  } else {
    device_info = this->encryption_enabled_ ? BTHOME_DEVICE_INFO_ENCRYPTED : BTHOME_DEVICE_INFO_UNENCRYPTED;
  }
  this->adv_data_[pos++] = device_info;

  size_t measurement_start = pos;

  this->adv_data_[pos++] = 0x00;  // Object ID: packet_id
  this->adv_data_[pos++] = this->packet_id_;

#ifdef USE_EVENT
  if (this->pending_events_) {
    pos += this->encode_event_measurements_(this->adv_data_ + pos, MAX_BLE_ADVERTISEMENT_SIZE - pos);
  }
#endif

  if (this->immediate_advertising_pending_) {
    switch (this->immediate_adv_type_) {
#ifdef USE_BINARY_SENSOR
      case ImmediateType::BINARY: {
        auto &measurement = this->binary_measurements_[this->immediate_adv_measurement_index_];
        if (measurement.sensor->has_state()) {
          pos += this->encode_binary_measurement_(this->adv_data_ + pos, MAX_BLE_ADVERTISEMENT_SIZE - pos,
                                                  measurement.object_id, measurement.sensor->state);
        }
        break;
      }
#endif
#ifdef USE_SENSOR
      case ImmediateType::SENSOR: {
        auto &measurement = this->measurements_[this->immediate_adv_measurement_index_];
        if (measurement.sensor->has_state() && !std::isnan(measurement.sensor->state)) {
          pos += this->encode_measurement_(this->adv_data_ + pos, MAX_BLE_ADVERTISEMENT_SIZE - pos, measurement);
        }
        break;
      }
#endif
#ifdef USE_EVENT
      case ImmediateType::EVENT:
        // Events are encoded above; nothing else to add here.
        break;
#endif
      default:
        break;
    }
  } else {
#ifdef USE_SENSOR
    if (!this->measurements_.empty()) {
        size_t start_idx = this->current_sensor_index_;
        size_t count = this->measurements_.size();
        size_t added = 0;
        for (size_t i = 0; i < count; i++) {
          size_t idx = (start_idx + i) % count;
          const auto &measurement = this->measurements_[idx];
          if (!measurement.sensor->has_state() || std::isnan(measurement.sensor->state)) continue;
          size_t encoded_size = 1 + measurement.data_bytes;
          if (pos + encoded_size > MAX_BLE_ADVERTISEMENT_SIZE) break;
          pos += this->encode_measurement_(this->adv_data_ + pos, MAX_BLE_ADVERTISEMENT_SIZE - pos, measurement);
          added++;
        }
        if (added > 0 && added < count) {
          this->current_sensor_index_ = (start_idx + added) % count;
        }
    }
#endif
#ifdef USE_BINARY_SENSOR
    if (!this->binary_measurements_.empty()) {
        size_t start_idx = this->current_binary_index_;
        size_t count = this->binary_measurements_.size();
        size_t added = 0;
        for (size_t i = 0; i < count; i++) {
          size_t idx = (start_idx + i) % count;
          const auto &measurement = this->binary_measurements_[idx];
          if (!measurement.sensor->has_state()) continue;
          if (pos + 2 > MAX_BLE_ADVERTISEMENT_SIZE) break;
          pos += this->encode_binary_measurement_(this->adv_data_ + pos, MAX_BLE_ADVERTISEMENT_SIZE - pos,
                                                   measurement.object_id, measurement.sensor->state);
          added++;
        }
        if (added > 0 && added < count) {
          this->current_binary_index_ = (start_idx + added) % count;
        }
    }
#endif
  }

  size_t measurement_len = pos - measurement_start;

  if (this->encryption_enabled_ && measurement_len > 0) {
    uint8_t plaintext[MAX_BLE_ADVERTISEMENT_SIZE];
    memcpy(plaintext, this->adv_data_ + measurement_start, measurement_len);

    uint8_t ciphertext[MAX_BLE_ADVERTISEMENT_SIZE];
    size_t ciphertext_len = 0;

    if (this->encrypt_payload_(plaintext, measurement_len, ciphertext, &ciphertext_len)) {
      size_t actual_ciphertext_len = ciphertext_len - 4;
      memcpy(this->adv_data_ + measurement_start, ciphertext, actual_ciphertext_len);
      pos = measurement_start + actual_ciphertext_len;

      this->adv_data_[pos++] = this->counter_ & 0xFF;
      this->adv_data_[pos++] = (this->counter_ >> 8) & 0xFF;
      this->adv_data_[pos++] = (this->counter_ >> 16) & 0xFF;
      this->adv_data_[pos++] = (this->counter_ >> 24) & 0xFF;

      memcpy(this->adv_data_ + pos, ciphertext + actual_ciphertext_len, 4);
      pos += 4;

      // ======================================================================
      // 【核心修改 3/3】发送后保存计数器到 RTC
      // ======================================================================
      this->counter_++;
#ifdef USE_ESP32
      g_bthome_counter = this->counter_;
#endif
      // ======================================================================
    }
  }

  this->adv_data_[service_data_len_pos] = pos - service_data_len_pos - 1;
  this->adv_data_len_ = pos;

  this->packet_id_++;
#ifdef USE_ESP32
  g_bthome_packet_id = this->packet_id_;
#endif

  ESP_LOGD(TAG, "Built advertisement data (%u bytes, packet_id=%u)", 
           (uint32_t)this->adv_data_len_, (uint8_t)(this->packet_id_ - 1));
}

void BTHome::build_scan_response_data_() {
  size_t pos = 0;
  this->scan_rsp_data_[pos++] = 2;     // Length
  this->scan_rsp_data_[pos++] = 0x0A;  // Type: TX Power Level
#ifdef USE_ESP32
  int8_t tx_power_dbm = static_cast<int8_t>(this->tx_power_esp32_) * 3 - 12;
#elif defined(USE_NRF52)
  int8_t tx_power_dbm = this->tx_power_nrf52_;
#else
  int8_t tx_power_dbm = 0;
#endif
  this->scan_rsp_data_[pos++] = static_cast<uint8_t>(tx_power_dbm);

  if (this->has_manufacturer_id_) {
    this->scan_rsp_data_[pos++] = 7;
    this->scan_rsp_data_[pos++] = 0xFF;
    this->scan_rsp_data_[pos++] = this->manufacturer_id_ & 0xFF;
    this->scan_rsp_data_[pos++] = (this->manufacturer_id_ >> 8) & 0xFF;
    uint32_t version = ESPHOME_VERSION_CODE;
    this->scan_rsp_data_[pos++] = version & 0xFF;
    this->scan_rsp_data_[pos++] = (version >> 8) & 0xFF;
    this->scan_rsp_data_[pos++] = (version >> 16) & 0xFF;
    this->scan_rsp_data_[pos++] = (version >> 24) & 0xFF;
  }

  if (!this->device_name_.empty()) {
    size_t remaining = MAX_BLE_ADVERTISEMENT_SIZE - pos;
    size_t max_name_len = remaining > 2 ? remaining - 2 : 0;
    size_t name_len = std::min(this->device_name_.length(), max_name_len);
    if (name_len > 0) {
      this->scan_rsp_data_[pos++] = name_len + 1;
      this->scan_rsp_data_[pos++] = (name_len < this->device_name_.length()) ? 0x08 : 0x09;
      memcpy(this->scan_rsp_data_ + pos, this->device_name_.c_str(), name_len);
      pos += name_len;
    }
  }
  this->scan_rsp_data_len_ = pos;
  ESP_LOGD(TAG, "Built scan response data (%u bytes)", (uint32_t)this->scan_rsp_data_len_);
}

void BTHome::start_advertising_() {
#ifdef USE_ESP32
  #ifdef USE_BTHOME_NIMBLE
  if (!this->nimble_initialized_) return;
  ble_gap_adv_set_data(this->adv_data_, this->adv_data_len_);
  if (this->scan_rsp_data_len_ > 0) ble_gap_adv_rsp_set_data(this->scan_rsp_data_, this->scan_rsp_data_len_);
  struct ble_gap_adv_params adv_params;
  memset(&adv_params, 0, sizeof(adv_params));
  adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
  adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
  adv_params.itvl_min = static_cast<uint16_t>(this->min_interval_ / 0.625f);
  adv_params.itvl_max = static_cast<uint16_t>(this->max_interval_ / 0.625f);
  ble_gap_adv_start(this->nimble_own_addr_type_, nullptr, BLE_HS_FOREVER, &adv_params, nullptr, nullptr);
  this->advertising_ = true;
  #else
  // Bluedroid...
  this->adv_data_set_ = false;
  this->scan_rsp_data_set_ = false;
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, this->tx_power_esp32_);
  esp_ble_gap_config_adv_data_raw(this->adv_data_, this->adv_data_len_);
  if (this->scan_rsp_data_len_ > 0) esp_ble_gap_config_scan_rsp_data_raw(this->scan_rsp_data_, this->scan_rsp_data_len_);
  esp_ble_gap_start_advertising(&this->ble_adv_params_);
  #endif
#endif
#ifdef USE_NRF52
  // NRF...
  bt_le_adv_start(&this->adv_param_, this->ad_, 2, this->sd_, 0); // Simplified for example
  this->advertising_ = true;
#endif
}

void BTHome::stop_advertising_() {
#ifdef USE_ESP32
  #ifdef USE_BTHOME_NIMBLE
  if (this->advertising_) { ble_gap_adv_stop(); this->advertising_ = false; }
  #else
  if (this->advertising_) { esp_ble_gap_stop_advertising(); }
  #endif
#endif
}

#if defined(USE_ESP32) && defined(USE_BTHOME_NIMBLE)
void BTHome::nimble_host_task_(void *param) { nimble_port_run(); nimble_port_freertos_deinit(); }
void BTHome::nimble_on_sync_() {
  ble_hs_id_infer_auto(0, &instance_->nimble_own_addr_type_);
  instance_->build_advertisement_data_();
  instance_->build_scan_response_data_();
  instance_->start_advertising_();
}
void BTHome::nimble_on_reset_(int reason) { instance_->advertising_ = false; }
#endif

#if defined(USE_ESP32) && defined(USE_BTHOME_BLUEDROID)
void BTHome::gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {}
#endif

#ifdef USE_SENSOR
size_t BTHome::encode_measurement_(uint8_t *data, size_t max_len, const SensorMeasurement &measurement) {
  size_t required_size = 1 + measurement.data_bytes;
  if (max_len < required_size) return 0;
  float value = measurement.sensor->state;
  size_t pos = 0;
  data[pos++] = measurement.object_id;
  double scaled = std::round(value / measurement.factor);
  if (measurement.is_signed) {
    int32_t encoded;
    switch (measurement.data_bytes) {
      case 1: encoded = static_cast<int8_t>(std::max(-128.0, std::min(127.0, scaled))); data[pos++] = encoded & 0xFF; break;
      case 2: encoded = static_cast<int16_t>(std::max(-32768.0, std::min(32767.0, scaled))); data[pos++] = encoded & 0xFF; data[pos++] = (encoded >> 8) & 0xFF; break;
      case 3: encoded = static_cast<int32_t>(std::max(-8388608.0, std::min(8388607.0, scaled))); data[pos++] = encoded & 0xFF; data[pos++] = (encoded >> 8) & 0xFF; data[pos++] = (encoded >> 16) & 0xFF; break;
      case 4: encoded = static_cast<int32_t>(scaled); data[pos++] = encoded & 0xFF; data[pos++] = (encoded >> 8) & 0xFF; data[pos++] = (encoded >> 16) & 0xFF; data[pos++] = (encoded >> 24) & 0xFF; break;
    }
  } else {
    uint32_t encoded;
    switch (measurement.data_bytes) {
      case 1: encoded = static_cast<uint8_t>(std::max(0.0, std::min(255.0, scaled))); data[pos++] = encoded & 0xFF; break;
      case 2: encoded = static_cast<uint16_t>(std::max(0.0, std::min(65535.0, scaled))); data[pos++] = encoded & 0xFF; data[pos++] = (encoded >> 8) & 0xFF; break;
      case 3: encoded = static_cast<uint32_t>(std::max(0.0, std::min(16777215.0, scaled))); data[pos++] = encoded & 0xFF; data[pos++] = (encoded >> 8) & 0xFF; data[pos++] = (encoded >> 16) & 0xFF; break;
      case 4: encoded = static_cast<uint32_t>(std::max(0.0, scaled)); data[pos++] = encoded & 0xFF; data[pos++] = (encoded >> 8) & 0xFF; data[pos++] = (encoded >> 16) & 0xFF; data[pos++] = (encoded >> 24) & 0xFF; break;
    }
  }
  return pos;
}
#endif

#ifdef USE_BINARY_SENSOR
size_t BTHome::encode_binary_measurement_(uint8_t *data, size_t max_len, uint8_t object_id, bool value) {
  if (max_len < 2) return 0;
  data[0] = object_id;
  data[1] = value ? 0x01 : 0x00;
  return 2;
}
#endif

#ifdef USE_EVENT
size_t BTHome::encode_event_measurements_(uint8_t *data, size_t max_len) {
  if (this->event_measurements_.empty() || !this->pending_events_) {
    return 0;
  }

  int highest_index = -1;
  for (size_t i = 0; i < this->event_measurements_.size(); i++) {
    if (this->pending_event_types_[i] != 0x00) {
      highest_index = static_cast<int>(i);
    }
  }

  if (highest_index < 0) {
    this->pending_events_ = false;
    return 0;
  }

  size_t pos = 0;
  for (size_t i = 0; i <= static_cast<size_t>(highest_index); i++) {
    if (max_len - pos < 2) {
      ESP_LOGW(TAG, "Not enough space for all events, remaining events will be sent later");
      break;
    }
    data[pos++] = BTHOME_OBJECT_ID_BUTTON_EVENT;
    data[pos++] = this->pending_event_types_[i];
    this->pending_event_types_[i] = 0x00;
  }

  this->pending_events_ = false;
  for (size_t i = 0; i < this->event_measurements_.size(); i++) {
    if (this->pending_event_types_[i] != 0x00) {
      this->pending_events_ = true;
      break;
    }
  }

  return pos;
}

bool BTHome::map_button_event_type_(const std::string &event_type, uint8_t *event_code) const {
  if (event_type == "none") {
    *event_code = BUTTON_EVENT_NONE;
  } else if (event_type == "press") {
    *event_code = BUTTON_EVENT_PRESS;
  } else if (event_type == "double_press") {
    *event_code = BUTTON_EVENT_DOUBLE_PRESS;
  } else if (event_type == "triple_press") {
    *event_code = BUTTON_EVENT_TRIPLE_PRESS;
  } else if (event_type == "long_press") {
    *event_code = BUTTON_EVENT_LONG_PRESS;
  } else if (event_type == "long_double_press") {
    *event_code = BUTTON_EVENT_LONG_DOUBLE_PRESS;
  } else if (event_type == "long_triple_press") {
    *event_code = BUTTON_EVENT_LONG_TRIPLE_PRESS;
  } else if (event_type == "hold_press" || event_type == "hold") {
    *event_code = BUTTON_EVENT_HOLD_PRESS;
  } else {
    return false;
  }
  return true;
}

void BTHome::queue_button_event_(size_t index, uint8_t event_code, bool advertise_immediately) {
  if (index >= this->event_measurements_.size()) {
    return;
  }

  this->pending_event_types_[index] = event_code;
  this->pending_events_ = true;

  if (advertise_immediately) {
    this->trigger_immediate_advertising_(0, ImmediateType::EVENT);
  } else {
    this->data_changed_ = true;
#ifdef USE_ESP32
    this->enable_loop();
#endif
  }
}
#endif

bool BTHome::encrypt_payload_(const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t *ciphertext_len) {
  if (!this->encryption_enabled_) return false;

  uint8_t nonce[13];

#ifdef USE_ESP32
  #ifdef USE_BTHOME_NIMBLE
    uint8_t mac[6];
    int rc = ble_hs_id_copy_addr(this->nimble_own_addr_type_, mac, nullptr);
    if (rc != 0) return false;
    for (int i = 0; i < 3; i++) {
      uint8_t temp = mac[i];
      mac[i] = mac[5 - i];
      mac[5 - i] = temp;
    }
    memcpy(nonce, mac, 6);
  #else
    const uint8_t *mac = esp_bt_dev_get_address();
    memcpy(nonce, mac, 6);
  #endif
#endif

#ifdef USE_NRF52
  bt_addr_le_t addr;
  size_t count = 1;
  bt_id_get(&addr, &count);
  memcpy(nonce, addr.a.val, 6);
#endif

  nonce[6] = BTHOME_SERVICE_UUID & 0xFF;
  nonce[7] = (BTHOME_SERVICE_UUID >> 8) & 0xFF;
  nonce[8] = this->trigger_based_ ? BTHOME_DEVICE_INFO_TRIGGER_ENCRYPTED : BTHOME_DEVICE_INFO_ENCRYPTED;
  nonce[9] = this->counter_ & 0xFF;
  nonce[10] = (this->counter_ >> 8) & 0xFF;
  nonce[11] = (this->counter_ >> 16) & 0xFF;
  nonce[12] = (this->counter_ >> 24) & 0xFF;

#ifdef USE_ESP32
  #ifdef USE_BTHOME_NIMBLE
    struct tc_ccm_mode_struct ctx;
    struct tc_aes_key_sched_struct sched;
    if (tc_aes128_set_encrypt_key(&sched, this->encryption_key_.data()) != TC_CRYPTO_SUCCESS) return false;
    if (tc_ccm_config(&ctx, &sched, nonce, sizeof(nonce), 4) != TC_CRYPTO_SUCCESS) return false;
    if (tc_ccm_generation_encryption(ciphertext, plaintext_len + 4, nullptr, 0, plaintext, plaintext_len, &ctx) != TC_CRYPTO_SUCCESS) return false;
  #else
    mbedtls_ccm_context ctx;
    mbedtls_ccm_init(&ctx);
    mbedtls_ccm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, this->encryption_key_.data(), 128);
    int ret = mbedtls_ccm_encrypt_and_tag(&ctx, plaintext_len, nonce, sizeof(nonce), nullptr, 0, plaintext, ciphertext, ciphertext + plaintext_len, 4);
    mbedtls_ccm_free(&ctx);
    if (ret != 0) return false;
  #endif
#endif

#ifdef USE_NRF52
  struct tc_ccm_mode_struct ctx;
  struct tc_aes_key_sched_struct sched;
  tc_aes128_set_encrypt_key(&sched, this->encryption_key_.data());
  tc_ccm_config(&ctx, &sched, nonce, sizeof(nonce), 4);
  tc_ccm_generation_encryption(ciphertext, plaintext_len + 4, nullptr, 0, plaintext, plaintext_len, &ctx);
#endif

  *ciphertext_len = plaintext_len + 4;
  return true;
}

}  // namespace bthome
}  // namespace esphome

#endif  // USE_ESP32 || USE_NRF52
