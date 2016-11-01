#include <ucontext.h>

#define DPL_USER                3
#define DPL_SYSTEM              0
#define MSR_GS_BASE             0xC0000101
#define MSR_DEBUG_CTL           0x1D9
#define RPL_MASK                3
#define SELECTOR_TABLE_INDEX    0x04
#define MTRR_TYPE_WB            6
#define EFLAGS_ALIGN_CHECK      0x40000
#define AMD64_TSS               9
#ifndef PAGE_SIZE
#define PAGE_SIZE               4096
#endif


#define MYPAGE_SIZE 4096
#define VMX_BASIC_MSR 0x480
#define FEATURE_CONTROL_MSR 0x3A
#define CPUID_VMX_BIT 5

#define STATUS_SUCESS		0
#define STATUS_NOT_AVAILABLE	-1
#define STATUS_NO_RESOURCES	-2
#define STATUS_NOT_PRESENT	-3

#define PML4E_ENTRY_COUNT 512
#define PDPTE_ENTRY_COUNT 512

/* Migrated from SimpleVisor/vmx.h */
/* exit reasons */
#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_VIRT_INTR   7
#define EXIT_REASON_PENDING_VIRT_NMI    8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_GETSEC              11
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_TRAP_FLAG   37
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MCE_DURING_VMENTRY  41

#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_ACCESS_GDTR_OR_IDTR 46
#define EXIT_REASON_ACCESS_LDTR_OR_TR   47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED     52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_RDRAND              57
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_RDSEED              61
#define EXIT_REASON_PML_FULL            62
#define EXIT_REASON_XSAVES              63
#define EXIT_REASON_XRSTORS             64
#define EXIT_REASON_PCOMMIT             65


#define CPU_BASED_VIRTUAL_INTR_PENDING          0x00000004
#define CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define CPU_BASED_HLT_EXITING                   0x00000080
#define CPU_BASED_INVLPG_EXITING                0x00000200
#define CPU_BASED_MWAIT_EXITING                 0x00000400
#define CPU_BASED_RDPMC_EXITING                 0x00000800
#define CPU_BASED_RDTSC_EXITING                 0x00001000
#define CPU_BASED_CR3_LOAD_EXITING              0x00008000
#define CPU_BASED_CR3_STORE_EXITING             0x00010000
#define CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define CPU_BASED_CR8_STORE_EXITING             0x00100000
#define CPU_BASED_TPR_SHADOW                    0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING           0x00400000
#define CPU_BASED_MOV_DR_EXITING                0x00800000
#define CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP            0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG             0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP           0x10000000
#define CPU_BASED_MONITOR_EXITING               0x20000000
#define CPU_BASED_PAUSE_EXITING                 0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000

#define PIN_BASED_EXT_INTR_MASK                 0x00000001
#define PIN_BASED_NMI_EXITING                   0x00000008
#define PIN_BASED_VIRTUAL_NMIS                  0x00000020
#define PIN_BASED_PREEMPT_TIMER                 0x00000040
#define PIN_BASED_POSTED_INTERRUPT              0x00000080

#define VM_EXIT_SAVE_DEBUG_CNTRLS               0x00000004
#define VM_EXIT_IA32E_MODE                      0x00000200
#define VM_EXIT_LOAD_PERF_GLOBAL_CTRL           0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VM_EXIT_SAVE_GUEST_PAT                  0x00040000
#define VM_EXIT_LOAD_HOST_PAT                   0x00080000
#define VM_EXIT_SAVE_GUEST_EFER                 0x00100000
#define VM_EXIT_LOAD_HOST_EFER                  0x00200000
#define VM_EXIT_SAVE_PREEMPT_TIMER              0x00400000
#define VM_EXIT_CLEAR_BNDCFGS                   0x00800000

#define VM_ENTRY_IA32E_MODE                     0x00000200
#define VM_ENTRY_SMM                            0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR             0x00000800
#define VM_ENTRY_LOAD_PERF_GLOBAL_CTRL          0x00002000
#define VM_ENTRY_LOAD_GUEST_PAT                 0x00004000
#define VM_ENTRY_LOAD_GUEST_EFER                0x00008000
#define VM_ENTRY_LOAD_BNDCFGS                   0x00010000

#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define SECONDARY_EXEC_ENABLE_EPT               0x00000002
#define SECONDARY_EXEC_DESCRIPTOR_TABLE_EXITING 0x00000004
#define SECONDARY_EXEC_ENABLE_RDTSCP            0x00000008
#define SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE   0x00000010
#define SECONDARY_EXEC_ENABLE_VPID              0x00000020
#define SECONDARY_EXEC_WBINVD_EXITING           0x00000040
#define SECONDARY_EXEC_UNRESTRICTED_GUEST       0x00000080
#define SECONDARY_EXEC_APIC_REGISTER_VIRT       0x00000100
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY    0x00000200
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING       0x00000400
#define SECONDARY_EXEC_ENABLE_INVPCID           0x00001000
#define SECONDARY_EXEC_ENABLE_VM_FUNCTIONS      0x00002000
#define SECONDARY_EXEC_ENABLE_VMCS_SHADOWING    0x00004000
#define SECONDARY_EXEC_ENABLE_PML               0x00020000
#define SECONDARY_EXEC_ENABLE_VIRT_EXCEPTIONS   0x00040000
#define SECONDARY_EXEC_XSAVES                   0x00100000
#define SECONDARY_EXEC_PCOMMIT                  0x00200000
#define SECONDARY_EXEC_TSC_SCALING              0x02000000

#define VMX_BASIC_REVISION_MASK                 0x7fffffff
#define VMX_BASIC_VMCS_SIZE_MASK                (0x1fffULL << 32)
#define VMX_BASIC_32BIT_ADDRESSES               (1ULL << 48)
#define VMX_BASIC_DUAL_MONITOR                  (1ULL << 49)
#define VMX_BASIC_MEMORY_TYPE_MASK              (0xfULL << 50)
#define VMX_BASIC_INS_OUT_INFO                  (1ULL << 54)
#define VMX_BASIC_DEFAULT1_ZERO                 (1ULL << 55)

#define VMX_EPT_EXECUTE_ONLY_BIT                (1ULL)
#define VMX_EPT_PAGE_WALK_4_BIT                 (1ULL << 6)
#define VMX_EPTP_UC_BIT                         (1ULL << 8)
#define VMX_EPTP_WB_BIT                         (1ULL << 14)
#define VMX_EPT_2MB_PAGE_BIT                    (1ULL << 16)
#define VMX_EPT_1GB_PAGE_BIT                    (1ULL << 17)
#define VMX_EPT_INVEPT_BIT                      (1ULL << 20)
#define VMX_EPT_AD_BIT                          (1ULL << 21)
#define VMX_EPT_EXTENT_CONTEXT_BIT              (1ULL << 25)
#define VMX_EPT_EXTENT_GLOBAL_BIT               (1ULL << 26)

/* MSRs & bits used for VMX enabling */
#define MSR_IA32_VMX_BASIC                      0x480
#define MSR_IA32_VMX_PINBASED_CTLS              0x481
#define MSR_IA32_VMX_PROCBASED_CTLS             0x482
#define MSR_IA32_VMX_EXIT_CTLS                  0x483
#define MSR_IA32_VMX_ENTRY_CTLS                 0x484
#define MSR_IA32_VMX_MISC                       0x485
#define MSR_IA32_VMX_CR0_FIXED0                 0x486
#define MSR_IA32_VMX_CR0_FIXED1                 0x487
#define MSR_IA32_VMX_CR4_FIXED0                 0x488
#define MSR_IA32_VMX_CR4_FIXED1                 0x489
#define MSR_IA32_VMX_VMCS_ENUM                  0x48a
#define MSR_IA32_VMX_PROCBASED_CTLS2            0x48b
#define MSR_IA32_VMX_EPT_VPID_CAP               0x48c
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS         0x48d
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS        0x48e
#define MSR_IA32_VMX_TRUE_EXIT_CTLS             0x48f
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS            0x490
#define IA32_FEATURE_CONTROL_MSR                0x3a
#define IA32_FEATURE_CONTROL_MSR_LOCK                     0x0001
#define IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_INSIDE_SMX  0x0002
#define IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX 0x0004
#define IA32_FEATURE_CONTROL_MSR_SENTER_PARAM_CTL         0x7f00
#define IA32_FEATURE_CONTROL_MSR_ENABLE_SENTER            0x8000

#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS   0x40000000
#define HYPERV_CPUID_INTERFACE                  0x40000001
#define HYPERV_CPUID_VERSION                    0x40000002
#define HYPERV_CPUID_FEATURES                   0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO           0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS           0x40000005

#define HYPERV_HYPERVISOR_PRESENT_BIT           0x80000000
#define HYPERV_CPUID_MIN                        0x40000005
#define HYPERV_CPUID_MAX                        0x4000ffff

/* Above is migrated from SimplerVisor/vmx.h */


/* VMCS Fields */
#define VMX_VPID					0x00000000
#define POSTED_INTR_NOTIFICATION_VECTOR			0x00000002
#define EPTP_INDEX					0x00000004

#define VMX_GUEST_ES_SEL				0x00000800
#define VMX_GUEST_CS_SEL				0x00000802
#define VMX_GUEST_SS_SEL				0x00000804
#define VMX_GUEST_DS_SEL				0x00000806
#define VMX_GUEST_FS_SEL				0x00000808
#define VMX_GUEST_GS_SEL				0x0000080a
#define VMX_GUEST_LDTR_SEL				0x0000080c
#define VMX_GUEST_TR_SEL				0x0000080e
#define VMX_GUEST_INTR_STATUS				0x00000810
#define VMX_GUEST_PML_INDEX				0x00000812
#define VMX_HOST_ES_SEL					0x00000c00
#define VMX_HOST_CS_SEL					0x00000c02
#define VMX_HOST_SS_SEL					0x00000c04
#define VMX_HOST_DS_SEL					0x00000c06
#define VMX_HOST_FS_SEL					0x00000c08
#define VMX_HOST_GS_SEL					0x00000c0a
#define VMX_HOST_TR_SEL					0x00000c0c
#define VMX_IO_BITMAP_A_FULL				0x00002000
#define VMX_IO_BITMAP_A_HIGH				0x00002001
#define VMX_IO_BITMAP_B_FULL				0x00002002
#define VMX_IO_BITMAP_B_HIGH				0x00002003
#define VMX_MSR_BITMAP_FULL                          0x00002004
#define VMX_MSR_BITMAP_HIGH                          0x00002005
#define VMX_EXIT_MSR_STORE_ADDR_FULL			0x00002006
#define VMX_EXIT_MSR_STORE_ADDR_HIGH			0x00002007
#define VMX_EXIT_MSR_LOAD_ADDR_FULL			0x00002008
#define VMX_EXIT_MSR_LOAD_ADDR_HIGH			0x00002009
#define VMX_ENTRY_MSR_LOAD_ADDR_FULL			0x0000200a
#define VMX_ENTRY_MSR_LOAD_ADDR_HIGH			0x0000200b
#define VMX_EXECUTIVE_VMCS_PTR_FULL                  0x0000200c
#define VMX_EXECUTIVE_VMCS_PTR_HIGH                  0x0000200d
#define VMX_TSC_OFFSET_FULL				0x00002010
#define VMX_TSC_OFFSET_HIGH				0x00002011
#define VMX_VIRTUAL_APIC_PAGE_ADDR_FULL			0x00002012
#define VMX_VIRTUAL_APIC_PAGE_ADDR_HIGH			0x00002013
#define VMX_APIC_ACCESS_ADDR_FULL			0x00002014
#define VMX_APIC_ACCESS_ADDR_HIGH			0x00002015
#define VMX_EPT_POINTER_FULL		             0x0000201a
#define VMX_EPT_POINTER_HIGH		             0x0000201b
#define VMX_VMS_LINK_PTR_FULL				0x00002800
#define VMX_VMS_LINK_PTR_HIGH				0x00002801
#define VMX_GUEST_IA32_DEBUGCTL_FULL			0x00002802
#define VMX_GUEST_IA32_DEBUGCTL_HIGH			0x00002803
#define VMX_GUEST_IA32_PAT_FULL                      0x00002804
#define VMX_GUEST_IA32_PAT_HIGH         	        0x00002805
#define VMX_GUEST_IA32_EFER_FULL                     0x00002806
#define VMX_GUEST_IA32_EFER_HIGH			0x00002807
#define VMX_GUEST_IA32_PERF_CTL_FULL                 0x00002808
#define VMX_GUEST_IA32_PERF_CTL_HIGH                 0x00002809
#define VMX_GUEST_PDPTE0_FULL	        		0x0000280A
#define VMX_GUEST_PDPTE0_HIGH				0x0000280B
#define VMX_GUEST_PDPTE1_FULL				0x0000280C
#define VMX_GUEST_PDPTE1_HIGH				0x0000280D
#define VMX_GUEST_PDPTE2_FULL				0x0000280E
#define VMX_GUEST_PDPTE2_HIGH				0x0000280F
#define VMX_GUEST_PDPTE3_FULL				0x00002810
#define VMX_GUEST_PDPTE3_HIGH				0x00002811
#define VMX_HOST_IA32_PAT_FULL                       0x00002C00
#define VMX_HOST_IA32_PAT_HIGH                       0x00002C01
#define VMX_HOST_IA32_EFER_FULL                      0x00002C02
#define VMX_HOST_IA32_EFER_HIGH                      0x00002C03
#define VMX_HOST_IA32_PERF_CTL_FULL                  0x00002C04
#define VMX_HOST_IA32_PERF_CTL_HIGH                  0x00002C05
#define VMX_PIN_VM_EXEC_CONTROLS			0x00004000
#define VMX_PROC_VM_EXEC_CONTROLS			0x00004002
#define VMX_EXCEPTION_BITMAP				0x00004004
#define VMX_PF_EC_MASK					0x00004006
#define VMX_PF_EC_MATCH					0x00004008
#define VMX_CR3_TARGET_COUNT				0x0000400a
#define VMX_EXIT_CONTROLS				0x0000400c
#define VMX_EXIT_MSR_STORE_COUNT			0x0000400e
#define VMX_EXIT_MSR_LOAD_COUNT				0x00004010
#define VMX_ENTRY_CONTROLS				0x00004012
#define VMX_ENTRY_MSR_LOAD_COUNT			0x00004014
#define VMX_ENTRY_INT_INFO_FIELD			0x00004016
#define VMX_ENTRY_EXCEPTION_EC				0x00004018
#define VMX_ENTRY_INSTR_LENGTH				0x0000401a
#define VMX_TPR_THRESHOLD				0x0000401c
#define VMX_PROC_VM_EXEC_CONTROLS2			0x0000401e
#define VMX_PLE_GAP			             0x00004020
#define VMX_PLE_WINDOW                               0x00004022
#define VMX_INSTR_ERROR					0x00004400
#define VMX_EXIT_REASON					0x00004402
#define VMX_EXIT_INT_INFO				0x00004404
#define VMX_EXIT_INT_EC					0x00004406
#define VMX_IDT_VEC_INFO_FIELD				0x00004408
#define VMX_IDT_VEC_EC					0x0000440a
#define VMX_EXIT_INSTR_LEN				0x0000440c
#define VMX_INSTR_INFO					0x0000440e
#define VMX_GUEST_ES_LIMIT				0x00004800
#define VMX_GUEST_CS_LIMIT				0x00004802
#define VMX_GUEST_SS_LIMIT				0x00004804
#define VMX_GUEST_DS_LIMIT				0x00004806
#define VMX_GUEST_FS_LIMIT				0x00004808
#define VMX_GUEST_GS_LIMIT				0x0000480a
#define VMX_GUEST_LDTR_LIMIT				0x0000480c
#define VMX_GUEST_TR_LIMIT				0x0000480e
#define VMX_GUEST_GDTR_LIMIT				0x00004810
#define VMX_GUEST_IDTR_LIMIT				0x00004812
#define VMX_GUEST_ES_ATTR				0x00004814
#define VMX_GUEST_CS_ATTR				0x00004816
#define VMX_GUEST_SS_ATTR				0x00004818
#define VMX_GUEST_DS_ATTR				0x0000481a
#define VMX_GUEST_FS_ATTR				0x0000481c
#define VMX_GUEST_GS_ATTR				0x0000481e
#define VMX_GUEST_LDTR_ATTR				0x00004820
#define VMX_GUEST_TR_ATTR				0x00004822
#define VMX_GUEST_INTERRUPTIBILITY_INFO			0x00004824
#define VMX_GUEST_ACTIVITY_STATE			0x00004826
#define VMX_GUEST_SMBASE                             0x00004828
#define VMX_GUEST_IA32_SYSENTER_CS			0x0000482a
#define VMX_GUEST_TIMER                              0x0000482E
#define VMX_HOST_IA32_SYSENTER_CS			0x00004c00
#define VMX_CR0_MASK					0x00006000
#define VMX_CR4_MASK					0x00006002
#define VMX_CR0_READ_SHADOW				0x00006004
#define VMX_CR4_READ_SHADOW				0x00006006
#define VMX_CR3_TARGET_0				0x00006008
#define VMX_CR3_TARGET_1				0x0000600a
#define VMX_CR3_TARGET_2				0x0000600c
#define VMX_CR3_TARGET_3				0x0000600e
#define VMX_EXIT_QUALIFICATION				0x00006400
#define VMX_IO_RCX					0x00006402
#define VMX_IO_RDI					0x00006406
#define VMX_GUEST_LINEAR_ADDR				0x0000640a
#define VMX_GUEST_PHYSICAL_ADDR_FULL			0x00002400
#define VMX_GUEST_PHYSICAL_ADDR_HIGH			0x00002401
#define VMX_GUEST_CR0					0x00006800
#define VMX_GUEST_CR3					0x00006802
#define VMX_GUEST_CR4					0x00006804
#define VMX_GUEST_ES_BASE				0x00006806
#define VMX_GUEST_CS_BASE				0x00006808
#define VMX_GUEST_SS_BASE				0x0000680a
#define VMX_GUEST_DS_BASE				0x0000680c
#define VMX_GUEST_FS_BASE				0x0000680e
#define VMX_GUEST_GS_BASE				0x00006810
#define VMX_GUEST_LDTR_BASE				0x00006812
#define VMX_GUEST_TR_BASE				0x00006814
#define VMX_GUEST_GDTR_BASE				0x00006816
#define VMX_GUEST_IDTR_BASE				0x00006818
#define VMX_GUEST_DR7					0x0000681a
#define VMX_GUEST_RSP					0x0000681c
#define VMX_GUEST_RIP					0x0000681e
#define VMX_GUEST_RFLAGS				0x00006820
#define VMX_GUEST_PENDING_DEBUG_EXCEPT			0x00006822
#define VMX_GUEST_IA32_SYSENTER_ESP			0x00006824
#define VMX_GUEST_IA32_SYSENTER_EIP			0x00006826
#define VMX_HOST_CR0					0x00006c00
#define VMX_HOST_CR3					0x00006c02
#define VMX_HOST_CR4					0x00006c04
#define VMX_HOST_FS_BASE				0x00006c06
#define VMX_HOST_GS_BASE				0x00006c08
#define VMX_HOST_TR_BASE				0x00006c0a
#define VMX_HOST_GDTR_BASE				0x00006c0c
#define VMX_HOST_IDTR_BASE				0x00006c0e
#define VMX_HOST_IA32_SYSENTER_ESP			0x00006c10
#define VMX_HOST_IA32_SYSENTER_EIP			0x00006c12
#define VMX_HOST_RSP					0x00006c14
#define VMX_HOST_RIP					0x00006c16

typedef struct _CALLBACK_CONTEXT
{
	uint64_t cr3;
	volatile long init_count;
	int32_t  f_cpu;
	int32_t  f_status;
} CALLBACK_CONTEXT, *PCALLBACK_CONTEXT;

typedef struct _desc_ptr {
        unsigned short limit;
        unsigned long base;
} desc_ptr __attribute__((packed)) ;

typedef struct _special_registers
{
	uint64_t cr0;
	uint64_t cr3;
	uint64_t cr4;
	uint64_t msr_gs_base;
	uint16_t tr;
	uint16_t ldtr;
	uint64_t dbg_ctl;
	uint64_t k_dr7;
	desc_ptr idtr;
	desc_ptr gdtr;
} special_registers, *pspecial_registers;

typedef struct _vmx_huge_pdpte
{
	union{
		struct{
			u64 read:1;
			u64 write:1;
			u64 exec:1;
			u64 type:3;
			u64 ign_pat:1;
			u64 large:1;
			u64 accessed:1;
			u64 dirty:1;
			u64 sw_use:2;
			u64 rsv:18;
			u64 pg_fr_no:18;
			u64 rsv_high:4;
			u64 sw_use_high:11;
			u64 supress_vme:1;
		};
		u64 as_ull;
	};
} vmx_huge_pdpte, *pvmx_huge_pdpte;

typedef struct _vmx_eptp
{
    union
    {
        struct
        {
            u64 type : 3;
            u64 pg_wk_len : 3;
            u64 enable_access_and_diry_flags : 1;
            u64 rsvd : 5;
            u64 pg_fr_no : 36;
            u64 rsvd_high : 16;
        };
        u64 as_ull;
    };
} vmx_eptp, *pvmx_eptp;

typedef struct _VP_DATA
{
	union
	{
		uint8_t stk_lmt[KERNEL_STACK_SIZE] __attribute__((aligned(PAGE_SIZE)));
		struct
		{
			special_registers 	sp_regs;
			ucontext_t		context;
			uint64_t 		sys_dir_tbl_base;
			uint64_t 		msr[17];
			uint64_t 		vmxon_phy_addr;
			uint64_t		vmcs_phy_addr;
			uint64_t		msr_bitmap_phy_addr;
			uint64_t		ept_pml4_phy_addr;
			uint32_t		ept_ctl;
		};
	};
	uint8_t	msr_bitmap[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
	VMX_EPML4E epml4[PML4E_ENTRY_COUNT] __attribute__((aligned(PAGE_SIZE)));
	vmx_huge_pdpte epdpt[PDPTE_ENTRY_COUNT] __attribute__((aligned(PAGE_SIZE)));
	
	VMX_VMCS vmxon __attribute__((aligned(PAGE_SIZE)));
	VMX_VMCS vmcs __attribute__((aligned(PAGE_SIZE)));
} VP_DATA, *PVP_DATA;


typedef struct _vp_state
{
    ucontext_t* regs;
    uintptr_t guest_rip;
    uintptr_t guest_rsp;
    uintptr_t guest_eflags;
    uint16_t exit_reason;
    uint8_t exit_vm;
} vp_state, *pvp_state;
