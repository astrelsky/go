//go:build amd64 && freebsd

package syscall

const (
	PROT_GPU_READ  = 0x10
	PROT_GPU_WRITE = 0x20
)

const (
	// SYS_NOSYS = 0;  // { int nosys(void); } syscall nosys_args int
	SYS_EXIT  = 1
	SYS_FORK  = 2
	SYS_READ  = 3
	SYS_WRITE = 4
	SYS_OPEN  = 5
	SYS_CLOSE = 6
	SYS_WAIT4 = 7
	//SYS_COMPAT.CREAT = 8
	SYS_LINK      = 9
	SYS_UNLINK    = 10
	SYS_OBS_EXECV = 11
	SYS_CHDIR     = 12
	SYS_FCHDIR    = 13
	SYS_MKNOD     = 14
	SYS_CHMOD     = 15
	SYS_CHOWN     = 16
	//SYS_OBS_{ = 17
	//SYS_COMPAT4.GETFSSTAT = 18
	//SYS_COMPAT.LSEEK = 19
	SYS_GETPID      = 20
	SYS_MOUNT       = 21
	SYS_UNMOUNT     = 22
	SYS_SETUID      = 23
	SYS_GETUID      = 24
	SYS_GETEUID     = 25
	SYS_PTRACE      = 26
	SYS_RECVMSG     = 27
	SYS_SENDMSG     = 28
	SYS_RECVFROM    = 29
	SYS_ACCEPT      = 30
	SYS_GETPEERNAME = 31
	SYS_GETSOCKNAME = 32
	SYS_ACCESS      = 33
	SYS_CHFLAGS     = 34
	SYS_FCHFLAGS    = 35
	SYS_SYNC        = 36
	SYS_KILL        = 37
	//SYS_COMPAT.STAT = 38
	SYS_GETPPID = 39
	//SYS_COMPAT.LSTAT = 40
	SYS_DUP = 41
	//SYS_COMPAT10.PIPE = 42
	SYS_GETEGID = 43
	SYS_PROFIL  = 44
	SYS_KTRACE  = 45
	//SYS_COMPAT.SIGACTION = 46
	SYS_GETGID = 47
	//SYS_COMPAT.SIGPROCMASK = 48
	SYS_GETLOGIN = 49
	SYS_SETLOGIN = 50
	//SYS_COMPAT.SIGPENDING = 52
	SYS_SIGALTSTACK = 53
	SYS_IOCTL       = 54
	SYS_REBOOT      = 55
	SYS_REVOKE      = 56
	SYS_SYMLINK     = 57
	SYS_READLINK    = 58
	SYS_EXECVE      = 59
	SYS_UMASK       = 60
	SYS_CHROOT      = 61
	//SYS_COMPAT.FSTAT = 62
	//SYS_COMPAT.GETKERNINFO = 63
	//SYS_COMPAT.GETPAGESIZE = 64
	SYS_MSYNC      = 65
	SYS_VFORK      = 66
	SYS_OBS_VREAD  = 67
	SYS_OBS_VWRITE = 68
	SYS_SBRK       = 69
	SYS_SSTK       = 70
	//SYS_COMPAT.MMAP = 71
	SYS_MUNMAP      = 73
	SYS_MPROTECT    = 74
	SYS_MADVISE     = 75
	SYS_OBS_VHANGUP = 76
	SYS_OBS_VLIMIT  = 77
	SYS_MINCORE     = 78
	SYS_GETGROUPS   = 79
	SYS_SETGROUPS   = 80
	SYS_GETPGRP     = 81
	SYS_SETPGID     = 82
	SYS_SETITIMER   = 83
	//SYS_COMPAT.WAIT = 84
	SYS_SWAPON    = 85
	SYS_GETITIMER = 86
	//SYS_COMPAT.GETHOSTNAME = 87
	//SYS_COMPAT.SETHOSTNAME = 88
	SYS_GETDTABLESIZE  = 89
	SYS_DUP2           = 90
	SYS_FCNTL          = 92
	SYS_SELECT         = 93
	SYS_FSYNC          = 95
	SYS_SETPRIORITY    = 96
	SYS_SOCKET         = 97
	SYS_CONNECT        = 98
	SYS_NETCONTROL     = 99
	SYS_GETPRIORITY    = 100
	SYS_NETABORT       = 101
	SYS_NETGETSOCKINFO = 102
	//SYS_COMPAT.SIGRETURN = 103
	SYS_BIND       = 104
	SYS_SETSOCKOPT = 105
	SYS_LISTEN     = 106
	SYS_OBS_VTIMES = 107
	//SYS_COMPAT.SIGVEC = 108
	//SYS_COMPAT.SIGBLOCK = 109
	//SYS_COMPAT.SIGSETMASK = 110
	//SYS_COMPAT.SIGSUSPEND = 111
	//SYS_COMPAT.SIGSTACK = 112
	SYS_SOCKETEX     = 113
	SYS_SOCKETCLOSE  = 114
	SYS_OBS_VTRACE   = 115
	SYS_GETTIMEOFDAY = 116
	SYS_GETRUSAGE    = 117
	SYS_GETSOCKOPT   = 118
	SYS_READV        = 120
	SYS_WRITEV       = 121
	SYS_SETTIMEOFDAY = 122
	SYS_FCHOWN       = 123
	SYS_FCHMOD       = 124
	SYS_NETGETIFLIST = 125
	SYS_SETREUID     = 126
	SYS_SETREGID     = 127
	SYS_RENAME       = 128
	//SYS_COMPAT.TRUNCATE = 129
	//SYS_COMPAT.FTRUNCATE = 130
	SYS_FLOCK      = 131
	SYS_MKFIFO     = 132
	SYS_SENDTO     = 133
	SYS_SHUTDOWN   = 134
	SYS_SOCKETPAIR = 135
	SYS_MKDIR      = 136
	SYS_RMDIR      = 137
	SYS_UTIMES     = 138
	//SYS_OBS_4.2 = 139
	SYS_ADJTIME  = 140
	SYS_KQUEUEEX = 141
	//SYS_COMPAT.GETHOSTID = 142
	//SYS_COMPAT.SETHOSTID = 143
	//SYS_COMPAT.GETRLIMIT = 144
	//SYS_COMPAT.SETRLIMIT = 145
	//SYS_COMPAT.KILLPG = 146
	SYS_SETSID = 147
	//SYS_COMPAT.QUOTA = 149
	//SYS_COMPAT.GETSOCKNAME = 150
	SYS_NLM_SYSCALL = 154
	SYS_NFSSVC      = 155
	//SYS_COMPAT.GETDIRENTRIES = 156
	//SYS_COMPAT4.STATFS = 157
	//SYS_COMPAT4.FSTATFS = 158
	//SYS_COMPAT4.GETDOMAINNAME = 162
	//SYS_COMPAT4.SETDOMAINNAME = 163
	//SYS_COMPAT4.UNAME = 164
	SYS_SYSARCH = 165
	SYS_RTPRIO  = 166
	SYS_SEMSYS  = 169
	SYS_MSGSYS  = 170
	SYS_SHMSYS  = 171
	//SYS_COMPAT6.PREAD = 173
	//SYS_COMPAT6.PWRITE = 174
	SYS_SETGID        = 181
	SYS_SETEGID       = 182
	SYS_SETEUID       = 183
	SYS_STAT          = 188
	SYS_FSTAT         = 189
	SYS_LSTAT         = 190
	SYS_PATHCONF      = 191
	SYS_FPATHCONF     = 192
	SYS_GETRLIMIT     = 194
	SYS_SETRLIMIT     = 195
	SYS_GETDIRENTRIES = 196
	//SYS_COMPAT6.MMAP = 197
	SYS___SYSCALL = 198
	//SYS_COMPAT6.LSEEK = 199
	//SYS_COMPAT6.TRUNCATE = 200
	//SYS_COMPAT6.FTRUNCATE = 201
	SYS___SYSCTL = 202
	SYS_MLOCK    = 203
	SYS_MUNLOCK  = 204
	SYS_FUTIMES  = 206
	SYS_GETPGID  = 207
	SYS_POLL     = 209
	SYS_LKMNOSYS = 210
	//SYS_COMPAT7.__SEMCTL = 220
	SYS_SEMGET = 221
	SYS_SEMOP  = 222
	//SYS_COMPAT7.MSGCTL = 224
	SYS_MSGGET = 225
	SYS_MSGSND = 226
	SYS_MSGRCV = 227
	SYS_SHMAT  = 228
	//SYS_COMPAT7.SHMCTL = 229
	SYS_SHMDT                = 230
	SYS_SHMGET               = 231
	SYS_CLOCK_GETTIME        = 232
	SYS_CLOCK_SETTIME        = 233
	SYS_CLOCK_GETRES         = 234
	SYS_KTIMER_CREATE        = 235
	SYS_KTIMER_DELETE        = 236
	SYS_KTIMER_SETTIME       = 237
	SYS_KTIMER_GETTIME       = 238
	SYS_KTIMER_GETOVERRUN    = 239
	SYS_NANOSLEEP            = 240
	SYS_FFCLOCK_GETCOUNTER   = 241
	SYS_FFCLOCK_SETESTIMATE  = 242
	SYS_FFCLOCK_GETESTIMATE  = 243
	SYS_CLOCK_GETCPUCLOCKID2 = 247
	SYS_MINHERIT             = 250
	SYS_RFORK                = 251
	SYS_ISSETUGID            = 253
	SYS_LCHOWN               = 254
	SYS_AIO_READ             = 255
	SYS_AIO_WRITE            = 256
	SYS_GETDENTS             = 272
	SYS_LCHMOD               = 274
	SYS_NETBSD_LCHOWN        = 275
	SYS_LUTIMES              = 276
	SYS_NETBSD_MSYNC         = 277
	SYS_PREADV               = 289
	SYS_PWRITEV              = 290
	//SYS_COMPAT4.FHSTATFS = 297
	SYS_KLDLOAD          = 304
	SYS_KLDUNLOAD        = 305
	SYS_KLDFIND          = 306
	SYS_KLDNEXT          = 307
	SYS_KLDSTAT          = 308
	SYS_KLDFIRSTMOD      = 309
	SYS_GETSID           = 310
	SYS_SETRESUID        = 311
	SYS_SETRESGID        = 312
	SYS_OBS_SIGNANOSLEEP = 313
	SYS_AIO_RETURN       = 314
	SYS_AIO_SUSPEND      = 315
	SYS_AIO_CANCEL       = 316
	SYS_AIO_ERROR        = 317
	//SYS_COMPAT6.AIO_READ = 318
	//SYS_COMPAT6.AIO_WRITE = 319
	//SYS_COMPAT6.LIO_LISTIO = 320
	SYS_YIELD                  = 321
	SYS_OBS_THR_SLEEP          = 322
	SYS_OBS_THR_WAKEUP         = 323
	SYS_MLOCKALL               = 324
	SYS_MUNLOCKALL             = 325
	SYS___GETCWD               = 326
	SYS_SCHED_SETPARAM         = 327
	SYS_SCHED_GETPARAM         = 328
	SYS_SCHED_SETSCHEDULER     = 329
	SYS_SCHED_GETSCHEDULER     = 330
	SYS_SCHED_YIELD            = 331
	SYS_SCHED_GET_PRIORITY_MAX = 332
	SYS_SCHED_GET_PRIORITY_MIN = 333
	SYS_SCHED_RR_GET_INTERVAL  = 334
	SYS_UTRACE                 = 335
	//SYS_COMPAT4.SENDFILE = 336
	SYS_KLDSYM        = 337
	SYS_NNPFS_SYSCALL = 339
	SYS_SIGPROCMASK   = 340
	SYS_SIGSUSPEND    = 341
	//SYS_COMPAT4.SIGACTION = 342
	SYS_SIGPENDING = 343
	//SYS_COMPAT4.SIGRETURN = 344
	SYS_SIGTIMEDWAIT                       = 345
	SYS_SIGWAITINFO                        = 346
	SYS_AIO_WAITCOMPLETE                   = 359
	SYS_GETRESUID                          = 360
	SYS_GETRESGID                          = 361
	SYS_KQUEUE                             = 362
	SYS_KEVENT                             = 363
	SYS___SETUGID                          = 374
	SYS_AFS3_SYSCALL                       = 377
	SYS_NMOUNT                             = 378
	SYS_MTYPEPROTECT                       = 379
	SYS___MAC_GET_PROC                     = 384
	SYS___MAC_SET_PROC                     = 385
	SYS___MAC_GET_FD                       = 386
	SYS___MAC_GET_FILE                     = 387
	SYS___MAC_SET_FD                       = 388
	SYS___MAC_SET_FILE                     = 389
	SYS_KENV                               = 390
	SYS_LCHFLAGS                           = 391
	SYS_UUIDGEN                            = 392
	SYS_SENDFILE                           = 393
	SYS_MAC_SYSCALL                        = 394
	SYS_GETFSSTAT                          = 395
	SYS_STATFS                             = 396
	SYS_FSTATFS                            = 397
	SYS_KSEM_CLOSE                         = 400
	SYS_KSEM_POST                          = 401
	SYS_KSEM_WAIT                          = 402
	SYS_KSEM_TRYWAIT                       = 403
	SYS_KSEM_INIT                          = 404
	SYS_KSEM_OPEN                          = 405
	SYS_KSEM_UNLINK                        = 406
	SYS_KSEM_GETVALUE                      = 407
	SYS_KSEM_DESTROY                       = 408
	SYS___MAC_GET_PID                      = 409
	SYS___MAC_GET_LINK                     = 410
	SYS___MAC_SET_LINK                     = 411
	SYS___MAC_EXECVE                       = 415
	SYS_SIGACTION                          = 416
	SYS_SIGRETURN                          = 417
	SYS_GETCONTEXT                         = 421
	SYS_SETCONTEXT                         = 422
	SYS_SWAPCONTEXT                        = 423
	SYS_SIGWAIT                            = 429
	SYS_THR_CREATE                         = 430
	SYS_THR_EXIT                           = 431
	SYS_THR_SELF                           = 432
	SYS_THR_KILL                           = 433
	SYS_KSEM_TIMEDWAIT                     = 441
	SYS_THR_SUSPEND                        = 442
	SYS_THR_WAKE                           = 443
	SYS_KLDUNLOADF                         = 444
	SYS__UMTX_OP                           = 454
	SYS_THR_NEW                            = 455
	SYS_SIGQUEUE                           = 456
	SYS_KMQ_OPEN                           = 457
	SYS_KMQ_SETATTR                        = 458
	SYS_KMQ_TIMEDRECEIVE                   = 459
	SYS_KMQ_TIMEDSEND                      = 460
	SYS_KMQ_NOTIFY                         = 461
	SYS_KMQ_UNLINK                         = 462
	SYS_THR_SET_NAME                       = 464
	SYS_AIO_FSYNC                          = 465
	SYS_RTPRIO_THREAD                      = 466
	SYS_PREAD                              = 475
	SYS_PWRITE                             = 476
	SYS_MMAP                               = 477
	SYS_LSEEK                              = 478
	SYS_TRUNCATE                           = 479
	SYS_FTRUNCATE                          = 480
	SYS_THR_KILL2                          = 481
	SYS_SHM_OPEN                           = 482
	SYS_SHM_UNLINK                         = 483
	SYS_CPUSET                             = 484
	SYS_CPUSET_SETID                       = 485
	SYS_CPUSET_GETID                       = 486
	SYS_CPUSET_GETAFFINITY                 = 487
	SYS_CPUSET_SETAFFINITY                 = 488
	SYS_FCHMODAT                           = 490
	SYS_FCHOWNAT                           = 491
	SYS_FSTATAT                            = 493
	SYS_FUTIMESAT                          = 494
	SYS_LINKAT                             = 495
	SYS_MKDIRAT                            = 496
	SYS_MKFIFOAT                           = 497
	SYS_MKNODAT                            = 498
	SYS_OPENAT                             = 499
	SYS_RENAMEAT                           = 501
	SYS_SYMLINKAT                          = 502
	SYS_UNLINKAT                           = 503
	SYS_GSSD_SYSCALL                       = 505
	SYS___SEMCTL                           = 510
	SYS_MSGCTL                             = 511
	SYS_SHMCTL                             = 512
	SYS_OBS_CAP_NEW                        = 514
	SYS___CAP_RIGHTS_GET                   = 515
	SYS_CAP_ENTER                          = 516
	SYS_CAP_GETMODE                        = 517
	SYS_PDKILL                             = 519
	SYS_PDGETPID                           = 520
	SYS_PSELECT                            = 522
	SYS_RCTL_GET_RACCT                     = 525
	SYS_RCTL_GET_RULES                     = 526
	SYS_RCTL_GET_LIMITS                    = 527
	SYS_RCTL_ADD_RULE                      = 528
	SYS_RCTL_REMOVE_RULE                   = 529
	SYS_REGMGR_CALL                        = 532
	SYS_JITSHM_CREATE                      = 533
	SYS_JITSHM_ALIAS                       = 534
	SYS_DL_GET_LIST                        = 535
	SYS_DL_GET_INFO                        = 536
	SYS_EVF_CREATE                         = 538
	SYS_EVF_DELETE                         = 539
	SYS_EVF_OPEN                           = 540
	SYS_EVF_CLOSE                          = 541
	SYS_EVF_WAIT                           = 542
	SYS_EVF_TRYWAIT                        = 543
	SYS_EVF_SET                            = 544
	SYS_EVF_CLEAR                          = 545
	SYS_EVF_CANCEL                         = 546
	SYS_QUERY_MEMORY_PROTECTION            = 547
	SYS_BATCH_MAP                          = 548
	SYS_OSEM_CREATE                        = 549
	SYS_OSEM_DELETE                        = 550
	SYS_OSEM_OPEN                          = 551
	SYS_OSEM_CLOSE                         = 552
	SYS_OSEM_WAIT                          = 553
	SYS_OSEM_TRYWAIT                       = 554
	SYS_OSEM_POST                          = 555
	SYS_OSEM_CANCEL                        = 556
	SYS_NAMEDOBJ_CREATE                    = 557
	SYS_NAMEDOBJ_DELETE                    = 558
	SYS_SET_VM_CONTAINER                   = 559
	SYS_DEBUG_INIT                         = 560
	SYS_SUSPEND_PROCESS                    = 561
	SYS_RESUME_PROCESS                     = 562
	SYS_OPMC_ENABLE                        = 563
	SYS_OPMC_DISABLE                       = 564
	SYS_OPMC_SET_CTL                       = 565
	SYS_OPMC_SET_CTR                       = 566
	SYS_OPMC_GET_CTR                       = 567
	SYS_BUDGET_CREATE                      = 568
	SYS_BUDGET_DELETE                      = 569
	SYS_BUDGET_GET                         = 570
	SYS_BUDGET_SET                         = 571
	SYS_VIRTUAL_QUERY                      = 572
	SYS_MDBG_CALL                          = 573
	SYS_OBS_SBLOCK_CREATE                  = 574
	SYS_OBS_SBLOCK_DELETE                  = 575
	SYS_OBS_SBLOCK_ENTER                   = 576
	SYS_OBS_SBLOCK_EXIT                    = 577
	SYS_OBS_SBLOCK_XENTER                  = 578
	SYS_OBS_SBLOCK_XEXIT                   = 579
	SYS_OBS_EPORT_CREATE                   = 580
	SYS_OBS_EPORT_DELETE                   = 581
	SYS_OBS_EPORT_TRIGGER                  = 582
	SYS_OBS_EPORT_OPEN                     = 583
	SYS_OBS_EPORT_CLOSE                    = 584
	SYS_IS_IN_SANDBOX                      = 585
	SYS_DMEM_CONTAINER                     = 586
	SYS_GET_AUTHINFO                       = 587
	SYS_MNAME                              = 588
	SYS_DYNLIB_DLOPEN                      = 589
	SYS_DYNLIB_DLCLOSE                     = 590
	SYS_DYNLIB_DLSYM                       = 591
	SYS_DYNLIB_GET_LIST                    = 592
	SYS_DYNLIB_GET_INFO                    = 593
	SYS_DYNLIB_LOAD_PRX                    = 594
	SYS_DYNLIB_UNLOAD_PRX                  = 595
	SYS_DYNLIB_DO_COPY_RELOCATIONS         = 596
	SYS_DYNLIB_PREPARE_DLCLOSE             = 597
	SYS_DYNLIB_GET_PROC_PARAM              = 598
	SYS_DYNLIB_PROCESS_NEEDED_AND_RELOCATE = 599
	SYS_SANDBOX_PATH                       = 600
	SYS_MDBG_SERVICE                       = 601
	SYS_RANDOMIZED_PATH                    = 602
	SYS_RDUP                               = 603
	SYS_DL_GET_METADATA                    = 604
	SYS_WORKAROUND8849                     = 605
	SYS_IS_DEVELOPMENT_MODE                = 606
	SYS_GET_SELF_AUTH_INFO                 = 607
	SYS_DYNLIB_GET_INFO_EX                 = 608
	SYS_BUDGET_GETID                       = 609
	SYS_BUDGET_GET_PTYPE                   = 610
	SYS_GET_PAGING_STATS_OF_ALL_THREADS    = 611
	SYS_GET_PROC_TYPE_INFO                 = 612
	SYS_GET_RESIDENT_COUNT                 = 613
	SYS_PREPARE_TO_SUSPEND_PROCESS         = 614
	SYS_GET_RESIDENT_FMEM_COUNT            = 615
	SYS_THR_GET_NAME                       = 616
	SYS_SET_GPO                            = 617
	SYS_GET_PAGING_STATS_OF_ALL_OBJECTS    = 618
	SYS_TEST_DEBUG_RWMEM                   = 619
	SYS_FREE_STACK                         = 620
	SYS_SUSPEND_SYSTEM                     = 621
	SYS_IPMIMGR_CALL                       = 622
	SYS_GET_GPO                            = 623
	SYS_GET_VM_MAP_TIMESTAMP               = 624
	SYS_OPMC_SET_HW                        = 625
	SYS_OPMC_GET_HW                        = 626
	SYS_GET_CPU_USAGE_ALL                  = 627
	SYS_MMAP_DMEM                          = 628
	SYS_PHYSHM_OPEN                        = 629
	SYS_PHYSHM_UNLINK                      = 630
	SYS_RESUME_INTERNAL_HDD                = 631
	SYS_THR_SUSPEND_UCONTEXT               = 632
	SYS_THR_RESUME_UCONTEXT                = 633
	SYS_THR_GET_UCONTEXT                   = 634
	SYS_THR_SET_UCONTEXT                   = 635
	SYS_SET_TIMEZONE_INFO                  = 636
	SYS_SET_PHYS_FMEM_LIMIT                = 637
	SYS_UTC_TO_LOCALTIME                   = 638
	SYS_LOCALTIME_TO_UTC                   = 639
	SYS_SET_UEVT                           = 640
	SYS_GET_CPU_USAGE_PROC                 = 641
	SYS_GET_MAP_STATISTICS                 = 642
	SYS_SET_CHICKEN_SWITCHES               = 643
	SYS_GET_KERNEL_MEM_STATISTICS          = 646
	SYS_GET_SDK_COMPILED_VERSION           = 647
	SYS_APP_STATE_CHANGE                   = 648
	SYS_DYNLIB_GET_OBJ_MEMBER              = 649
	SYS_BUDGET_GET_PTYPE_OF_BUDGET         = 650
	SYS_PREPARE_TO_RESUME_PROCESS          = 651
	SYS_PROCESS_TERMINATE                  = 652
	SYS_BLOCKPOOL_OPEN                     = 653
	SYS_BLOCKPOOL_MAP                      = 654
	SYS_BLOCKPOOL_UNMAP                    = 655
	SYS_DYNLIB_GET_INFO_FOR_LIBDBG         = 656
	SYS_BLOCKPOOL_BATCH                    = 657
	SYS_FDATASYNC                          = 658
	SYS_DYNLIB_GET_LIST2                   = 659
	SYS_DYNLIB_GET_INFO2                   = 660
	SYS_AIO_SUBMIT                         = 661
	SYS_AIO_MULTI_DELETE                   = 662
	SYS_AIO_MULTI_WAIT                     = 663
	SYS_AIO_MULTI_POLL                     = 664
	SYS_AIO_GET_DATA                       = 665
	SYS_AIO_MULTI_CANCEL                   = 666
	SYS_GET_BIO_USAGE_ALL                  = 667
	SYS_AIO_CREATE                         = 668
	SYS_AIO_SUBMIT_CMD                     = 669
	SYS_AIO_INIT                           = 670
	SYS_GET_PAGE_TABLE_STATS               = 671
	SYS_DYNLIB_GET_LIST_FOR_LIBDBG         = 672
	SYS_BLOCKPOOL_MOVE                     = 673
	SYS_VIRTUAL_QUERY_ALL                  = 674
	SYS_RESERVE_2MB_PAGE                   = 675
	SYS_CPUMODE_YIELD                      = 676
	SYS_WAIT6                              = 677
	SYS_CAP_RIGHTS_LIMIT                   = 678
	SYS_CAP_IOCTLS_LIMIT                   = 679
	SYS_CAP_IOCTLS_GET                     = 680
	SYS_CAP_FCNTLS_LIMIT                   = 681
	SYS_CAP_FCNTLS_GET                     = 682
	SYS_BINDAT                             = 683
	SYS_CONNECTAT                          = 684
	SYS_CHFLAGSAT                          = 685
	SYS_ACCEPT4                            = 686
	SYS_PIPE2                              = 687
	SYS_AIO_MLOCK                          = 688
	SYS_PROCCTL                            = 689
	SYS_PPOLL                              = 690
	SYS_FUTIMENS                           = 691
	SYS_UTIMENSAT                          = 692
	SYS_NUMA_GETAFFINITY                   = 693
	SYS_NUMA_SETAFFINITY                   = 694
	SYS_APR_SUBMIT                         = 700
	SYS_APR_RESOLVE                        = 701
	SYS_APR_STAT                           = 702
	SYS_APR_WAIT                           = 703
	SYS_APR_CTRL                           = 704
	SYS_GET_PHYS_PAGE_SIZE                 = 705
	SYS_BEGIN_APP_MOUNT                    = 706
	SYS_END_APP_MOUNT                      = 707
	SYS_FSC2H_CTRL                         = 708
	SYS_STREAMWRITE                        = 709
	SYS_APP_SAVE                           = 710
	SYS_APP_RESTORE                        = 711
	SYS_SAVED_APP_DELETE                   = 712
	SYS_GET_PPR_SDK_COMPILED_VERSION       = 713
	SYS_NOTIFY_APP_EVENT                   = 714
	SYS_IOREQ                              = 715
	SYS_OPENINTR                           = 716
	SYS_DL_GET_INFO_2                      = 717
	SYS_ACINFO_ADD                         = 718
	SYS_ACINFO_DELETE                      = 719
	SYS_ACINFO_GET_ALL_FOR_COREDUMP        = 720
	SYS_AMPR_CTRL_DEBUG                    = 721
	SYS_WORKSPACE_CTRL                     = 722
	SYS_NOTIFY_A53_BIND_PROGRESS           = 723
)
