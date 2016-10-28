
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

/* MSRs & bits used for VMX enabling */
#define MSR_IA32_VMX_BASIC                      	0x480

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
#define VMX_PROC_VM_EXEC_CONTROLS2			0x0000401E
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

typedef struct _VP_DATA
{
	union
	{
		uint8_t stk_lmt[KERNEL_STACK_SIZE] __attribute__((aligned(PAGE_SIZE)));
		struct
		{
			special_registers 	sp_regs;
			struct task_struct	context;
			uint64_t 		sys_dir_tbl_base;
			uint64_t 		msr[17];
			uint64_t 		vmxon_phy_addr;
			uint64_t		vmcs_phy_addr;
			uint64_t		msr_bitmap_phy_addr;
			uint64_t		ept_pml4_phy_addr;
			uint32_t		ept_controls;
		};
	};
	uint8_t	msr_bitmap[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
	VMX_EPML4E epml4[PML4E_ENTRY_COUNT] __attribute__((aligned(PAGE_SIZE)));
	vmx_huge_pdpte epdpt[PDPTE_ENTRY_COUNT] __attribute__((aligned(PAGE_SIZE)));
	
	VMX_VMCS vmxon __attribute__((aligned(PAGE_SIZE)));
	VMX_VMCS vmcs __attribute__((aligned(PAGE_SIZE)));
} VP_DATA, *PVP_DATA;


