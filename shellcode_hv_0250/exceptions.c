#include "exceptions.h"
#include "../include/config_0250.h"
#include "utils.h"
#include <stdint.h>

#define IDT_PA cave_hv_idt

struct interrupt_frame {
  uint64_t rip;
  uint64_t cs;
  uint64_t rflags;
  uint64_t rsp;
  uint64_t ss;
};

struct idt_gate {
  uint16_t offset_low;
  uint16_t selector;
  uint8_t ist;
  uint8_t type_attributes;
  uint16_t offset_middle;
  uint32_t offset_high;
  uint32_t reserved;
} __attribute__((packed));

struct idt_descriptor {
  uint16_t limit;
  uint64_t base;
} __attribute__((packed));

static volatile uint32_t idt_state;

static __attribute__((noreturn)) void
exception_stop(uint8_t vector, struct interrupt_frame *frame, uint64_t error) {
  disable_intr();
  uart_exception_trace(vector, get_cpu(), frame->rip, error);
  for (;;)
    halt();
}

__attribute__((interrupt)) static void
handle_nmi(struct interrupt_frame *frame) {
  (void)frame;
}

__attribute__((interrupt)) static void
handle_ud(struct interrupt_frame *frame) {
  exception_stop(6, frame, 0);
}

__attribute__((interrupt)) static void
handle_gp(struct interrupt_frame *frame, uint64_t error) {
  exception_stop(13, frame, error);
}

__attribute__((interrupt)) static void
handle_pf(struct interrupt_frame *frame, uint64_t error) {
  exception_stop(14, frame, error);
}

static void set_gate(struct idt_gate *idt, uint8_t vector, void *handler,
                     uint16_t selector) {
  uint64_t address = (uint64_t)handler;
  struct idt_gate *gate = &idt[vector];
  gate->offset_low = (uint16_t)address;
  gate->selector = selector;
  gate->ist = 0;
  gate->type_attributes = 0x8E;
  gate->offset_middle = (uint16_t)(address >> 16);
  gate->offset_high = (uint32_t)(address >> 32);
  gate->reserved = 0;
}

void install_exception_idt(void) {
  struct idt_gate *idt = (struct idt_gate *)IDT_PA;
  if (__sync_bool_compare_and_swap(&idt_state, 0, 1)) {
    zero_bytes(idt, 0x1000);
    set_gate(idt, 2, handle_nmi, 0x10);
    set_gate(idt, 6, handle_ud, 0x10);
    set_gate(idt, 13, handle_gp, 0x10);
    set_gate(idt, 14, handle_pf, 0x10);
    __atomic_store_n(&idt_state, 2, __ATOMIC_RELEASE);
  } else {
    while (__atomic_load_n(&idt_state, __ATOMIC_ACQUIRE) != 2)
      __asm__ volatile("pause");
  }

  struct idt_descriptor descriptor = {
      .limit = 0x1000 - 1,
      .base = IDT_PA,
  };
  __asm__ volatile("lidt %0" : : "m"(descriptor) : "memory");
}
