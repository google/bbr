/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * Definitions of strace-style symbols for Linux.
 * Allows us to map from symbolic strings to integers for system call inputs.
 */

#if linux

#include "symbols.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include <linux/sockios.h>

#include "tcp.h"

/* A table of platform-specific string->int mappings. */
struct int_symbol platform_symbols_table[] = {
	{ SOL_IP,                           "SOL_IP"                          },
	{ SOL_IPV6,                         "SOL_IPV6"                        },
	{ SOL_TCP,                          "SOL_TCP"                         },
	{ SOL_UDP,                          "SOL_UDP"                         },

	{ SO_ACCEPTCONN,                    "SO_ACCEPTCONN"                   },
	{ SO_ATTACH_FILTER,                 "SO_ATTACH_FILTER"                },
	{ SO_BINDTODEVICE,                  "SO_BINDTODEVICE"                 },
	{ SO_BROADCAST,                     "SO_BROADCAST"                    },
	{ SO_BSDCOMPAT,                     "SO_BSDCOMPAT"                    },
	{ SO_DEBUG,                         "SO_DEBUG"                        },
	{ SO_DETACH_FILTER,                 "SO_DETACH_FILTER"                },
	{ SO_DONTROUTE,                     "SO_DONTROUTE"                    },
	{ SO_ERROR,                         "SO_ERROR"                        },
	{ SO_KEEPALIVE,                     "SO_KEEPALIVE"                    },
	{ SO_LINGER,                        "SO_LINGER"                       },
	{ SO_NO_CHECK,                      "SO_NO_CHECK"                     },
	{ SO_OOBINLINE,                     "SO_OOBINLINE"                    },
	{ SO_PASSCRED,                      "SO_PASSCRED"                     },
	{ SO_PEERCRED,                      "SO_PEERCRED"                     },
	{ SO_PEERNAME,                      "SO_PEERNAME"                     },
	{ SO_PEERSEC,                       "SO_PEERSEC"                      },
	{ SO_PRIORITY,                      "SO_PRIORITY"                     },
	{ SO_RCVBUF,                        "SO_RCVBUF"                       },
	{ SO_RCVLOWAT,                      "SO_RCVLOWAT"                     },
	{ SO_RCVTIMEO,                      "SO_RCVTIMEO"                     },
	{ SO_REUSEADDR,                     "SO_REUSEADDR"                    },
	{ SO_REUSEPORT,                     "SO_REUSEPORT"                    },
	{ SO_SECURITY_AUTHENTICATION,       "SO_SECURITY_AUTHENTICATION"      },
	{ SO_SECURITY_ENCRYPTION_NETWORK,   "SO_SECURITY_ENCRYPTION_NETWORK"  },
	{ SO_SECURITY_ENCRYPTION_TRANSPORT, "SO_SECURITY_ENCRYPTION_TRANSPORT"},
	{ SO_SNDBUF,                        "SO_SNDBUF"                       },
	{ SO_SNDLOWAT,                      "SO_SNDLOWAT"                     },
	{ SO_SNDTIMEO,                      "SO_SNDTIMEO"                     },
	{ SO_TIMESTAMP,                     "SO_TIMESTAMP"                    },
	{ SO_TYPE,                          "SO_TYPE"                         },

	{ IP_TOS,                           "IP_TOS"                          },
	{ IP_MTU_DISCOVER,                  "IP_MTU_DISCOVER"                 },
	{ IP_PMTUDISC_WANT,                 "IP_PMTUDISC_WANT"                },
	{ IP_PMTUDISC_DONT,                 "IP_PMTUDISC_DONT"                },
	{ IP_PMTUDISC_DO,                   "IP_PMTUDISC_DO"                  },
	{ IP_PMTUDISC_PROBE,                "IP_PMTUDISC_PROBE"               },
#ifdef IP_MTU
	{ IP_MTU,                           "IP_MTU"                          },
#endif
#ifdef IPV6_MTU
	{ IPV6_MTU,                         "IPV6_MTU"                        },
#endif

	{ TCP_NODELAY,                      "TCP_NODELAY"                     },
	{ TCP_MAXSEG,                       "TCP_MAXSEG"                      },
	{ TCP_CORK,                         "TCP_CORK"                        },
	{ TCP_KEEPIDLE,                     "TCP_KEEPIDLE"                    },
	{ TCP_KEEPINTVL,                    "TCP_KEEPINTVL"                   },
	{ TCP_KEEPCNT,                      "TCP_KEEPCNT"                     },
	{ TCP_SYNCNT,                       "TCP_SYNCNT"                      },
	{ TCP_LINGER2,                      "TCP_LINGER2"                     },
	{ TCP_DEFER_ACCEPT,                 "TCP_DEFER_ACCEPT"                },
	{ TCP_WINDOW_CLAMP,                 "TCP_WINDOW_CLAMP"                },
	{ TCP_INFO,                         "TCP_INFO"                        },
	{ TCP_QUICKACK,                     "TCP_QUICKACK"                    },
	{ TCP_CONGESTION,                   "TCP_CONGESTION"                  },
	{ TCP_MD5SIG,                       "TCP_MD5SIG"                      },
	{ TCP_COOKIE_TRANSACTIONS,          "TCP_COOKIE_TRANSACTIONS"         },
	{ TCP_THIN_LINEAR_TIMEOUTS,         "TCP_THIN_LINEAR_TIMEOUTS"        },
	{ TCP_THIN_DUPACK,                  "TCP_THIN_DUPACK"                 },
	{ TCP_USER_TIMEOUT,                 "TCP_USER_TIMEOUT"                },

	{ O_RDONLY,                         "O_RDONLY"                        },
	{ O_WRONLY,                         "O_WRONLY"                        },
	{ O_RDWR,                           "O_RDWR"                          },
	{ O_ACCMODE,                        "O_ACCMODE"                       },
	{ O_CREAT,                          "O_CREAT"                         },
	{ O_EXCL,                           "O_EXCL"                          },
	{ O_NOCTTY,                         "O_NOCTTY"                        },
	{ O_TRUNC,                          "O_TRUNC"                         },
	{ O_APPEND,                         "O_APPEND"                        },
	{ O_NONBLOCK,                       "O_NONBLOCK"                      },

	{ F_DUPFD,                          "F_DUPFD"                         },
	{ F_GETFD,                          "F_GETFD"                         },
	{ F_SETFD,                          "F_SETFD"                         },
	{ F_GETFL,                          "F_GETFL"                         },
	{ F_SETFL,                          "F_SETFL"                         },
	{ F_GETLK,                          "F_GETLK"                         },
	{ F_SETLK,                          "F_SETLK"                         },
	{ F_SETLKW,                         "F_SETLKW"                        },
	{ F_GETOWN,                         "F_GETOWN"                        },
	{ F_SETOWN,                         "F_SETOWN"                        },
	{ F_SETSIG,                         "F_SETSIG"                        },
	{ F_GETSIG,                         "F_GETSIG"                        },
	{ F_GETOWN,                         "F_GETOWN"                        },
	{ F_SETOWN,                         "F_SETOWN"                        },
	{ F_SETLK,                          "F_SETLK"                         },
	{ F_SETLKW,                         "F_SETLKW"                        },
	{ F_GETLK,                          "F_GETLK"                         },
	{ F_SETLK64,                        "F_SETLK64"                       },
	{ F_SETLKW64,                       "F_SETLKW64"                      },
	{ F_GETLK64,                        "F_GETLK64"                       },
	{ F_SETLEASE,                       "F_SETLEASE"                      },
	{ F_GETLEASE,                       "F_GETLEASE"                      },
	{ F_NOTIFY,                         "F_NOTIFY"                        },
	{ F_DUPFD_CLOEXEC,                  "F_DUPFD_CLOEXEC"                 },
	{ FD_CLOEXEC,                       "FD_CLOEXEC"                      },

	{ LOCK_SH,                          "LOCK_SH"                         },
	{ LOCK_EX,                          "LOCK_EX"                         },
	{ LOCK_NB,                          "LOCK_NB"                         },
	{ LOCK_UN,                          "LOCK_UN"                         },

	{ F_RDLCK,                          "F_RDLCK"                         },
	{ F_WRLCK,                          "F_WRLCK"                         },
	{ F_UNLCK,                          "F_UNLCK"                         },
	{ F_EXLCK,                          "F_EXLCK"                         },
	{ F_SHLCK,                          "F_SHLCK"                         },

	{ SEEK_SET,                         "SEEK_SET"                        },
	{ SEEK_CUR,                         "SEEK_CUR"                        },
	{ SEEK_END,                         "SEEK_END"                        },

	{ MSG_OOB,                          "MSG_OOB"                         },
	{ MSG_DONTROUTE,                    "MSG_DONTROUTE"                   },
	{ MSG_PEEK,                         "MSG_PEEK"                        },
	{ MSG_CTRUNC,                       "MSG_CTRUNC"                      },
	{ MSG_PROXY,                        "MSG_PROXY"                       },
	{ MSG_EOR,                          "MSG_EOR"                         },
	{ MSG_WAITALL,                      "MSG_WAITALL"                     },
	{ MSG_TRUNC,                        "MSG_TRUNC"                       },
	{ MSG_CTRUNC,                       "MSG_CTRUNC"                      },
	{ MSG_ERRQUEUE,                     "MSG_ERRQUEUE"                    },
	{ MSG_DONTWAIT,                     "MSG_DONTWAIT"                    },
	{ MSG_CONFIRM,                      "MSG_CONFIRM"                     },
	{ MSG_FIN,                          "MSG_FIN"                         },
	{ MSG_SYN,                          "MSG_SYN"                         },
	{ MSG_RST,                          "MSG_RST"                         },
	{ MSG_NOSIGNAL,                     "MSG_NOSIGNAL"                    },
	{ MSG_MORE,                         "MSG_MORE"                        },
	{ MSG_CMSG_CLOEXEC,                 "MSG_CMSG_CLOEXEC"                },
	{ MSG_FASTOPEN,                     "MSG_FASTOPEN"                    },

#ifdef SIOCINQ
	{ SIOCINQ,                          "SIOCINQ"                         },
#endif

#ifdef FIONREAD
	{ FIONREAD,                         "FIONREAD"                        },
#endif

	{ POLLIN,                           "POLLIN"                          },
	{ POLLPRI,                          "POLLPRI"                         },
	{ POLLOUT,                          "POLLOUT"                         },
#ifdef POLLRDNORM
	{ POLLRDNORM,                       "POLLRDNORM"                      },
#endif
#ifdef POLLRDBAND
	{ POLLRDBAND,                       "POLLRDBAND"                      },
#endif
#ifdef POLLWRNORM
	{ POLLWRNORM,                       "POLLWRNORM"                      },
#endif
#ifdef POLLWRBAND
	{ POLLWRBAND,                       "POLLWRBAND"                      },
#endif

#ifdef POLLMSG
	{ POLLMSG,                          "POLLMSG"                         },
#endif
#ifdef POLLREMOVE
	{ POLLREMOVE,                       "POLLREMOVE"                      },
#endif
#ifdef POLLRDHUP
	{ POLLRDHUP,                        "POLLRDHUP"                       },
#endif
	{ POLLERR,                          "POLLERR"                         },
	{ POLLHUP,                          "POLLHUP"                         },
	{ POLLNVAL,                         "POLLNVAL"                        },

	{ EPERM,                            "EPERM"                           },
	{ ENOENT,                           "ENOENT"                          },
	{ ESRCH,                            "ESRCH"                           },
	{ EINTR,                            "EINTR"                           },
	{ EIO,                              "EIO"                             },
	{ ENXIO,                            "ENXIO"                           },
	{ E2BIG,                            "E2BIG"                           },
	{ ENOEXEC,                          "ENOEXEC"                         },
	{ EBADF,                            "EBADF"                           },
	{ ECHILD,                           "ECHILD"                          },
	{ EAGAIN,                           "EAGAIN"                          },
	{ ENOMEM,                           "ENOMEM"                          },
	{ EACCES,                           "EACCES"                          },
	{ EFAULT,                           "EFAULT"                          },
	{ ENOTBLK,                          "ENOTBLK"                         },
	{ EBUSY,                            "EBUSY"                           },
	{ EEXIST,                           "EEXIST"                          },
	{ EXDEV,                            "EXDEV"                           },
	{ ENODEV,                           "ENODEV"                          },
	{ ENOTDIR,                          "ENOTDIR"                         },
	{ EISDIR,                           "EISDIR"                          },
	{ EINVAL,                           "EINVAL"                          },
	{ ENFILE,                           "ENFILE"                          },
	{ EMFILE,                           "EMFILE"                          },
	{ ENOTTY,                           "ENOTTY"                          },
	{ ETXTBSY,                          "ETXTBSY"                         },
	{ EFBIG,                            "EFBIG"                           },
	{ ENOSPC,                           "ENOSPC"                          },
	{ ESPIPE,                           "ESPIPE"                          },
	{ EROFS,                            "EROFS"                           },
	{ EMLINK,                           "EMLINK"                          },
	{ EPIPE,                            "EPIPE"                           },
	{ EDOM,                             "EDOM"                            },
	{ ERANGE,                           "ERANGE"                          },
	{ EDEADLK,                          "EDEADLK"                         },
	{ ENAMETOOLONG,                     "ENAMETOOLONG"                    },
	{ ENOLCK,                           "ENOLCK"                          },
	{ ENOSYS,                           "ENOSYS"                          },
	{ ENOTEMPTY,                        "ENOTEMPTY"                       },
	{ ELOOP,                            "ELOOP"                           },
	{ EWOULDBLOCK,                      "EWOULDBLOCK"                     },
	{ ENOMSG,                           "ENOMSG"                          },
	{ EIDRM,                            "EIDRM"                           },
	{ ECHRNG,                           "ECHRNG"                          },
	{ EL2NSYNC,                         "EL2NSYNC"                        },
	{ EL3HLT,                           "EL3HLT"                          },
	{ EL3RST,                           "EL3RST"                          },
	{ ELNRNG,                           "ELNRNG"                          },
	{ EUNATCH,                          "EUNATCH"                         },
	{ ENOCSI,                           "ENOCSI"                          },
	{ EL2HLT,                           "EL2HLT"                          },
	{ EBADE,                            "EBADE"                           },
	{ EBADR,                            "EBADR"                           },
	{ EXFULL,                           "EXFULL"                          },
	{ ENOANO,                           "ENOANO"                          },
	{ EBADRQC,                          "EBADRQC"                         },
	{ EBADSLT,                          "EBADSLT"                         },
	{ EDEADLOCK,                        "EDEADLOCK"                       },
	{ EBFONT,                           "EBFONT"                          },
	{ ENOSTR,                           "ENOSTR"                          },
	{ ENODATA,                          "ENODATA"                         },
	{ ETIME,                            "ETIME"                           },
	{ ENOSR,                            "ENOSR"                           },
	{ ENONET,                           "ENONET"                          },
	{ ENOPKG,                           "ENOPKG"                          },
	{ EREMOTE,                          "EREMOTE"                         },
	{ ENOLINK,                          "ENOLINK"                         },
	{ EADV,                             "EADV"                            },
	{ ESRMNT,                           "ESRMNT"                          },
	{ ECOMM,                            "ECOMM"                           },
	{ EPROTO,                           "EPROTO"                          },
	{ EMULTIHOP,                        "EMULTIHOP"                       },
	{ EDOTDOT,                          "EDOTDOT"                         },
	{ EBADMSG,                          "EBADMSG"                         },
	{ EOVERFLOW,                        "EOVERFLOW"                       },
	{ ENOTUNIQ,                         "ENOTUNIQ"                        },
	{ EBADFD,                           "EBADFD"                          },
	{ EREMCHG,                          "EREMCHG"                         },
	{ ELIBACC,                          "ELIBACC"                         },
	{ ELIBBAD,                          "ELIBBAD"                         },
	{ ELIBSCN,                          "ELIBSCN"                         },
	{ ELIBMAX,                          "ELIBMAX"                         },
	{ ELIBEXEC,                         "ELIBEXEC"                        },
	{ EILSEQ,                           "EILSEQ"                          },
	{ ERESTART,                         "ERESTART"                        },
	{ ESTRPIPE,                         "ESTRPIPE"                        },
	{ EUSERS,                           "EUSERS"                          },
	{ ENOTSOCK,                         "ENOTSOCK"                        },
	{ EDESTADDRREQ,                     "EDESTADDRREQ"                    },
	{ EMSGSIZE,                         "EMSGSIZE"                        },
	{ EPROTOTYPE,                       "EPROTOTYPE"                      },
	{ ENOPROTOOPT,                      "ENOPROTOOPT"                     },
	{ EPROTONOSUPPORT,                  "EPROTONOSUPPORT"                 },
	{ ESOCKTNOSUPPORT,                  "ESOCKTNOSUPPORT"                 },
	{ EOPNOTSUPP,                       "EOPNOTSUPP"                      },
	{ EPFNOSUPPORT,                     "EPFNOSUPPORT"                    },
	{ EAFNOSUPPORT,                     "EAFNOSUPPORT"                    },
	{ EADDRINUSE,                       "EADDRINUSE"                      },
	{ EADDRNOTAVAIL,                    "EADDRNOTAVAIL"                   },
	{ ENETDOWN,                         "ENETDOWN"                        },
	{ ENETUNREACH,                      "ENETUNREACH"                     },
	{ ENETRESET,                        "ENETRESET"                       },
	{ ECONNABORTED,                     "ECONNABORTED"                    },
	{ ECONNRESET,                       "ECONNRESET"                      },
	{ ENOBUFS,                          "ENOBUFS"                         },
	{ EISCONN,                          "EISCONN"                         },
	{ ENOTCONN,                         "ENOTCONN"                        },
	{ ESHUTDOWN,                        "ESHUTDOWN"                       },
	{ ETOOMANYREFS,                     "ETOOMANYREFS"                    },
	{ ETIMEDOUT,                        "ETIMEDOUT"                       },
	{ ECONNREFUSED,                     "ECONNREFUSED"                    },
	{ EHOSTDOWN,                        "EHOSTDOWN"                       },
	{ EHOSTUNREACH,                     "EHOSTUNREACH"                    },
	{ EALREADY,                         "EALREADY"                        },
	{ EINPROGRESS,                      "EINPROGRESS"                     },
	{ ESTALE,                           "ESTALE"                          },
	{ EUCLEAN,                          "EUCLEAN"                         },
	{ ENOTNAM,                          "ENOTNAM"                         },
	{ ENAVAIL,                          "ENAVAIL"                         },
	{ EISNAM,                           "EISNAM"                          },
	{ EREMOTEIO,                        "EREMOTEIO"                       },
	{ EDQUOT,                           "EDQUOT"                          },
	{ ENOMEDIUM,                        "ENOMEDIUM"                       },
	{ EMEDIUMTYPE,                      "EMEDIUMTYPE"                     },
	{ ECANCELED,                        "ECANCELED"                       },
	{ ENOKEY,                           "ENOKEY"                          },
	{ EKEYEXPIRED,                      "EKEYEXPIRED"                     },
	{ EKEYREVOKED,                      "EKEYREVOKED"                     },
	{ EKEYREJECTED,                     "EKEYREJECTED"                    },
	{ EOWNERDEAD,                       "EOWNERDEAD"                      },
	{ ENOTRECOVERABLE,                  "ENOTRECOVERABLE"                 },
	{ ERFKILL,                          "ERFKILL"                         },

	/* Sentinel marking the end of the table. */
	{ 0, NULL },
};

struct int_symbol *platform_symbols(void)
{
	return platform_symbols_table;
}

#endif  /* linux */
