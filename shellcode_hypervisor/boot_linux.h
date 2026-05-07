
#define MSR_EFER 0xc0000080
#define EFER_SVM (1ULL << 12) // Bit 12: Secure Virtual Machine Enable

// // Virtual Machine Control Register (VM_CR)
#define MSR_VM_CR 0xc0010114
#define VM_CR_R_INIT (1ULL << 1) // Bit 1: Intercept INIT

// // MTRRs (Memory Type Range Registers)
#define MSR_MTRR4kBase 0x00000268
#define MSR_MTRRVarBase 0x00000200

#define VRAM_BASE (0x470000000 - info.vram_size)

#define FB_BASE 0xf400000000

#define ACPI_RSDP_ADDRESS 0x7fd8e014

#define AMDGPU_MMIO_BASE 0xe0600000

#define RCC_CONFIG_MEMSIZE 0x378c

#define GCMC_VM_FB_OFFSET 0xa5ac
#define GCMC_VM_LOCAL_HBM_ADDRESS_START 0xa5d4
#define GCMC_VM_LOCAL_HBM_ADDRESS_END 0xa5d8
#define GCMC_VM_FB_LOCATION_BASE 0xa600
#define GCMC_VM_FB_LOCATION_TOP 0xa604

#define MMMC_VM_FB_OFFSET 0x6a15c
#define MMMC_VM_LOCAL_HBM_ADDRESS_START 0x6a184
#define MMMC_VM_LOCAL_HBM_ADDRESS_END 0x6a188
#define MMMC_VM_FB_LOCATION_BASE 0x6a1b0
#define MMMC_VM_FB_LOCATION_TOP 0x6a1b4

#define MMHUBBUB_WHITELIST_BASE_ADDR_0 0x24850
#define MMHUBBUB_WHITELIST_TOP_ADDR_0 0x24854
#define DCHUBBUB_WHITELIST_BASE_ADDR_0 0x24878
#define DCHUBBUB_WHITELIST_TOP_ADDR_0 0x2487c

#define AMDIOMMU_MMIO_BASE 0xfdd80000
#define AMDIOMMU_CTRL 0x18

#define MAXCPU 16

void entry(void);
void boot_linux(void);
