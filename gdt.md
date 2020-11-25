# GDT

```rust
//! Global descriptor table

use core::mem;
use x86::segmentation::load_cs;
use x86::bits64::task::TaskStateSegment;
use x86::Ring;
use x86::dtables::{self, DescriptorTablePointer};
use x86::segmentation::{self, Descriptor as SegmentDescriptor, SegmentSelector};
use x86::task;

use crate::paging::PAGE_SIZE;

pub const GDT_NULL: usize = 0;             // 0 空操作
pub const GDT_KERNEL_CODE: usize = 1;      // 1 内核代码
pub const GDT_KERNEL_DATA: usize = 2;      // 2 内核数据
pub const GDT_KERNEL_TLS: usize = 3;       // 3 内核线程局部存储(Thread Local Storage)
pub const GDT_USER_CODE: usize = 4;        // 4 用户代码
pub const GDT_USER_DATA: usize = 5;        // 5 用户数据
pub const GDT_USER_TLS: usize = 6;         // 6 用户线程局部存储
pub const GDT_TSS: usize = 7;              // 7 任务状态段(Task State Segment, TSS)
pub const GDT_TSS_HIGH: usize = 8;         // 8 高任务状态段 （不知道这个 高 是什么意思，可能是高优先级）

pub const GDT_A_PRESENT: u8 = 1 << 7;      // 10000000
pub const GDT_A_RING_0: u8 = 0 << 5;       // 00000000   ring0是特权级别，下面的ring1，ring2，ring3都是，windows只用ring0和ring3，用户用3，操作系统用0
pub const GDT_A_RING_1: u8 = 1 << 5;       // 00100000   一般不用
pub const GDT_A_RING_2: u8 = 2 << 5;       // 01000000   一般不用
pub const GDT_A_RING_3: u8 = 3 << 5;       // 01100000   用户模式和内核模式都可以用
pub const GDT_A_SYSTEM: u8 = 1 << 4;       // 00010000   系统指令
pub const GDT_A_EXECUTABLE: u8 = 1 << 3;   // 00001000
pub const GDT_A_CONFORMING: u8 = 1 << 2;   // 00000100
pub const GDT_A_PRIVILEGE: u8 = 1 << 1;    // 00000010   特权指令
pub const GDT_A_DIRTY: u8 = 1;             // 00000001
pub const GDT_A_TSS_AVAIL: u8 = 0x9;       // 00001001   TSS可用，可立即调用
pub const GDT_A_TSS_BUSY: u8 = 0xB;        // 00001011   TSS繁忙，暂时不可调用

pub const GDT_F_PAGE_SIZE: u8 = 1 << 7;            // 10000000  页大小
pub const GDT_F_PROTECTED_MODE: u8 = 1 << 6;       // 01000000  保护模式，内核模式？
pub const GDT_F_LONG_MODE: u8 = 1 << 5;            // 00100000  用户模式？

// 初始化GDTR寄存器的值  GDT一共由64位组成
static mut INIT_GDTR: DescriptorTablePointer<SegmentDescriptor> = DescriptorTablePointer {
    limit: 0,                //   段界限 （20位）
    base: 0 as *const SegmentDescriptor        // 段基址 （44位）
};

// 初始化 全局描述表
static mut INIT_GDT: [GdtEntry; 4] = [
    // Null
    GdtEntry::new(0, 0, 0, 0),
    // Kernel code
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE, GDT_F_LONG_MODE),
    // Kernel data
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_LONG_MODE),
    // Kernel TLS
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_LONG_MODE)
];

// GDTR寄存器，针对本地线程的GDTR寄存器的使用初始化
#[thread_local]
pub static mut GDTR: DescriptorTablePointer<SegmentDescriptor> = DescriptorTablePointer {
    limit: 0,
    base: 0 as *const SegmentDescriptor
};
// 针对本地线程的GDT创建
#[thread_local]
pub static mut GDT: [GdtEntry; 9] = [
    // Null
    GdtEntry::new(0, 0, 0, 0),
    // Kernel code
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE, GDT_F_LONG_MODE),
    // Kernel data
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_LONG_MODE),
    // Kernel TLS
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_0 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_LONG_MODE),
    // User code
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_EXECUTABLE | GDT_A_PRIVILEGE, GDT_F_LONG_MODE),
    // User data
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_LONG_MODE),
    // User TLS
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_SYSTEM | GDT_A_PRIVILEGE, GDT_F_LONG_MODE),
    // TSS
    GdtEntry::new(0, 0, GDT_A_PRESENT | GDT_A_RING_3 | GDT_A_TSS_AVAIL, 0),
    // TSS must be 16 bytes long, twice the normal size
    GdtEntry::new(0, 0, 0, 0),
];

#[thread_local]
pub static mut TSS: TaskStateSegment = TaskStateSegment {
    reserved: 0,
    rsp: [0; 3],
    reserved2: 0,
    ist: [0; 7],
    reserved3: 0,
    reserved4: 0,
    iomap_base: 0xFFFF
};

pub unsafe fn set_tcb(pid: usize) {
    GDT[GDT_USER_TLS].set_offset((crate::USER_TCB_OFFSET + pid * PAGE_SIZE) as u32);
}

#[cfg(feature = "pti")]
pub unsafe fn set_tss_stack(stack: usize) {
    use super::pti::{PTI_CPU_STACK, PTI_CONTEXT_STACK};
    TSS.rsp[0] = (PTI_CPU_STACK.as_ptr() as usize + PTI_CPU_STACK.len()) as u64;
    PTI_CONTEXT_STACK = stack;
}

#[cfg(not(feature = "pti"))]
pub unsafe fn set_tss_stack(stack: usize) {
    TSS.rsp[0] = stack as u64;
}

// Initialize GDT
pub unsafe fn init() {
    // Setup the initial GDT with TLS, so we can setup the TLS GDT (a little confusing)
    // This means that each CPU will have its own GDT, but we only need to define it once as a thread local
    INIT_GDTR.limit = (INIT_GDT.len() * mem::size_of::<GdtEntry>() - 1) as u16;
    INIT_GDTR.base = INIT_GDT.as_ptr() as *const SegmentDescriptor;

    // Load the initial GDT, before we have access to thread locals
    dtables::lgdt(&INIT_GDTR);

    // Load the segment descriptors
    load_cs(SegmentSelector::new(GDT_KERNEL_CODE as u16, Ring::Ring0));
    segmentation::load_ds(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_es(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_fs(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_gs(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_ss(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
}

/// Initialize GDT with TLS
/// 使用TLS（线程局部存储）初始化GDT，应该是线程调用
pub unsafe fn init_paging(tcb_offset: usize, stack_offset: usize) {
    // Set the TLS segment to the offset of the Thread Control Block
    // 将TLS段设置为线程控制块的偏移量
    INIT_GDT[GDT_KERNEL_TLS].set_offset(tcb_offset as u32);

    // Load the initial GDT, before we have access to thread locals
    // 在访问线程局部变量之前先加载初始化后的GDT
    dtables::lgdt(&INIT_GDTR);

    // Load the segment descriptors
    // 加载段描述符
    segmentation::load_fs(SegmentSelector::new(GDT_KERNEL_TLS as u16, Ring::Ring0));

    // Now that we have access to thread locals, setup the AP's individual GDT
    // 现在我们可以访问线程局部变量，设置AP的单独GDT
    GDTR.limit = (GDT.len() * mem::size_of::<GdtEntry>() - 1) as u16;
    GDTR.base = GDT.as_ptr() as *const SegmentDescriptor;

    // Set the TLS segment to the offset of the Thread Control Block
    // 将TLS段设置为线程控制块的偏移量
    GDT[GDT_KERNEL_TLS].set_offset(tcb_offset as u32);

    // Set the User TLS segment to the offset of the user TCB
    // TCB线程控制块
    // 将用户TLS段设置为用户TCB的偏移量
    set_tcb(0);

    // We can now access our TSS, which is a thread local
    // 访问TSS（任务状态表），本地线程
    GDT[GDT_TSS].set_offset(&TSS as *const _ as u32);
    GDT[GDT_TSS].set_limit(mem::size_of::<TaskStateSegment>() as u32);

    // Set the stack pointer when coming back from userspace
    // 从用户空间返回时设置堆栈指针
    set_tss_stack(stack_offset);

    // Load the new GDT, which is correctly located in thread local storage
    // 加载新的正确地位于线程本地存储中的GDT
    dtables::lgdt(&GDTR);

    // Reload the segment descriptors
    // 重新加载段描述符
    load_cs(SegmentSelector::new(GDT_KERNEL_CODE as u16, Ring::Ring0));
    segmentation::load_ds(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_es(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_fs(SegmentSelector::new(GDT_KERNEL_TLS as u16, Ring::Ring0));
    segmentation::load_gs(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));
    segmentation::load_ss(SegmentSelector::new(GDT_KERNEL_DATA as u16, Ring::Ring0));

    // Load the task register
    task::load_tr(SegmentSelector::new(GDT_TSS as u16, Ring::Ring0));
}

#[derive(Copy, Clone, Debug)]
#[repr(packed)]
// 64位GDT （每一项对应寄存器的地址还不清楚）
pub struct GdtEntry {
    pub limitl: u16,
    pub offsetl: u16,
    pub offsetm: u8,
    pub access: u8,
    pub flags_limith: u8,
    pub offseth: u8
}
// GDTentry功能
impl GdtEntry {
    // 新建GDTentry
    pub const fn new(offset: u32, limit: u32, access: u8, flags: u8) -> Self {
        GdtEntry {
            limitl: limit as u16,        // 段界限的低16位
            offsetl: offset as u16,      // offset的低16位
            offsetm: (offset >> 16) as u8,   // offset的高16位中的低8位给到access  
            access,
            flags_limith: flags & 0xF0 | ((limit >> 16) as u8) & 0x0F,   // 标志位高4位与段界限的高16位中的低4位取或，flags_limith的高4位是标志位的高4位，低4位是段界限的16-19位
            // 分页
            offseth: (offset >> 24) as u8    // offset高8位
        }
    }
    // 设置offset
    pub fn set_offset(&mut self, offset: u32) {
        self.offsetl = offset as u16;
        self.offsetm = (offset >> 16) as u8;
        self.offseth = (offset >> 24) as u8;
    }
    // 设置段界限和flag
    pub fn set_limit(&mut self, limit: u32) {
        self.limitl = limit as u16;
        self.flags_limith = self.flags_limith & 0xF0 | ((limit >> 16) as u8) & 0x0F;
    }
}
```

## GDT的含义和作用

*GDT可以被放在内存的任何位置，那么当程序员通过段寄存器来引用一个段描述符时，CPU必须知道GDT的入口，也就是基地址放在哪里，所以Intel的设计者门提供了一个寄存器GDTR用来存放GDT的入口地址，程序员将GDT设定在内存中某个位置之后，可以通过LGDT指令将GDT的入口地址装入此寄存器，从此以后，CPU就根据此寄存器中的内容作为GDT的入口来访问GDT了。*

## TLS的含义和作用

*如果需要在一个线程内部的各个函数调用都能访问、但其它线程不能访问的变量（被称为static memory local to a thread 线程局部静态变量），就需要新的机制来实现。这就是TLS。*

## TSS的含义和作用

*TSS 全称task state segment，是指在操作系统进程管理的过程中，任务（进程）切换时的任务现场信息。*

*TSS工作细节  TSS在任务切换过程中起着重要作用，通过它实现任务的挂起和恢复。所谓任务切换是指，挂起当前正在执行的任务，恢复或启动另一任务的执行。在任务切换过程中，首先，处理器中各寄存器的当前值被自动保存到TR（任务寄存器）所指定的TSS中；然后，下一任务的TSS的选择子被装入TR；最后，从TR所指定的TSS中取出各寄存器的值送到处理器的各寄存器中。由此可见，通过在TSS中保存任务现场各寄存器状态的完整映象，实现任务的切换。*

## GDTentry

flag_limith GDT_flag 在这采取了分页的方式一共8位，包含4位的flag和4位的段界限
limitl 段界限，16位
access 访问权限，8位
offset （不知道是啥）应该是基址，32位

- **下面的GDTR寄存器分配顺序还不清楚，大概是这样子**

|limitl|offsetl|offsetm|offseth|access|flag_limith|
|:---:|:---:|:---:|:---:|:---:|:---:|
|16|16|8|8|8|8|
