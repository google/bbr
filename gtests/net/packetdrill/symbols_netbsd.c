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
 * Definitions of strace-style symbols for NetBSD.
 * Allows us to map from symbolic strings to integers for system call inputs.
 */

#if defined(__NetBSD__)

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

#include "tcp.h"

/* A table of platform-specific string->int mappings. */
struct int_symbol platform_symbols_table[] = {

	/* /usr/include/sys/socket.h */
	{ SO_DEBUG,                         "SO_DEBUG"                        },
	{ SO_ACCEPTCONN,                    "SO_ACCEPTCONN"                   },
	{ SO_REUSEADDR,                     "SO_REUSEADDR"                    },
	{ SO_KEEPALIVE,                     "SO_KEEPALIVE"                    },
	{ SO_DONTROUTE,                     "SO_DONTROUTE"                    },
	{ SO_BROADCAST,                     "SO_BROADCAST"                    },
	{ SO_USELOOPBACK,                   "SO_USELOOPBACK"                  },
	{ SO_LINGER,                        "SO_LINGER"                       },
	{ SO_OOBINLINE,                     "SO_OOBINLINE"                    },
	{ SO_REUSEPORT,                     "SO_REUSEPORT"                    },
	{ SO_NOSIGPIPE,                     "SO_NOSIGPIPE"                    },
	{ SO_ACCEPTFILTER,                  "SO_ACCEPTFILTER"                 },
	{ SO_TIMESTAMP,                     "SO_TIMESTAMP"                    },
	{ SO_SNDBUF,                        "SO_SNDBUF"                       },
	{ SO_RCVBUF,                        "SO_RCVBUF"                       },
	{ SO_SNDLOWAT,                      "SO_SNDLOWAT"                     },
	{ SO_RCVLOWAT,                      "SO_RCVLOWAT"                     },
	{ SO_ERROR,                         "SO_ERROR"                        },
	{ SO_TYPE,                          "SO_TYPE"                         },
	{ SO_OVERFLOWED,                    "SO_OVERFLOWED"                   },
	{ SO_NOHEADER,                      "SO_NOHEADER"                     },
	{ SO_SNDTIMEO,                      "SO_SNDTIMEO"                     },
	{ SO_RCVTIMEO,                      "SO_RCVTIMEO"                     },

	/* /usr/include/netinet/tcp.h */
	{ TCP_NODELAY,                      "TCP_NODELAY"                     },
	{ TCP_MAXSEG,                       "TCP_MAXSEG"                      },
	{ TCP_KEEPIDLE,                     "TCP_KEEPIDLE"                    },
	{ TCP_KEEPINTVL,                    "TCP_KEEPINTVL"                   },
	{ TCP_KEEPCNT,                      "TCP_KEEPCNT"                     },
	{ TCP_KEEPINIT,                     "TCP_KEEPINIT"                    },
	{ TCP_MD5SIG,                       "TCP_MD5SIG"                      },
	{ TCP_CONGCTL,                      "TCP_CONGCTL"                     },

	/* /usr/include/sys/fcntl.h */
	{ O_RDONLY,                         "O_RDONLY"                        },
	{ O_WRONLY,                         "O_WRONLY"                        },
	{ O_RDWR,                           "O_RDWR"                          },
	{ O_ACCMODE,                        "O_ACCMODE"                       },
	{ FREAD,                            "FREAD"                           },
	{ FWRITE,                           "FWRITE"                          },
	{ O_NONBLOCK,                       "O_NONBLOCK"                      },
	{ O_APPEND,                         "O_APPEND"                        },
	{ O_SHLOCK,                         "O_SHLOCK"                        },
	{ O_EXLOCK,                         "O_EXLOCK"                        },
	{ O_ASYNC,                          "O_ASYNC"                         },
	{ O_SYNC,                           "O_SYNC"                          },
	{ O_NOFOLLOW,                       "O_NOFOLLOW"                      },
	{ O_CREAT,                          "O_CREAT"                         },
	{ O_TRUNC,                          "O_TRUNC"                         },
	{ O_EXCL,                           "O_EXCL"                          },
	{ O_NOCTTY,                         "O_NOCTTY"                        },
	{ O_DSYNC,                          "O_DSYNC"                         },
	{ O_RSYNC,                          "O_RSYNC"                         },
	{ O_ALT_IO,                         "O_ALT_IO"                        },
	{ O_DIRECT,                         "O_DIRECT"                        },
	{ O_DIRECTORY,                      "O_DIRECTORY"                     },
	{ O_CLOEXEC,                        "O_CLOEXEC"                       },
	{ O_NOSIGPIPE,                      "O_NOSIGPIPE"                     },
	{ FAPPEND,                          "FAPPEND"                         },
	{ FASYNC,                           "FASYNC"                          },
	{ O_FSYNC,                          "O_FSYNC"                         },
	{ FNDELAY,                          "FNDELAY"                         },
	{ O_NDELAY,                         "O_NDELAY"                        },
	{ F_DUPFD,                          "F_DUPFD"                         },
	{ F_GETFD,                          "F_GETFD"                         },
	{ F_SETFD,                          "F_SETFD"                         },
	{ F_GETFL,                          "F_GETFL"                         },
	{ F_SETFL,                          "F_SETFL"                         },
	{ F_GETOWN,                         "F_GETOWN"                        },
	{ F_SETOWN,                         "F_SETOWN"                        },
	{ F_GETLK,                          "F_GETLK"                         },
	{ F_SETLK,                          "F_SETLK"                         },
	{ F_SETLKW,                         "F_SETLKW"                        },
	{ F_CLOSEM,                         "F_CLOSEM"                        },
	{ F_MAXFD,                          "F_MAXFD"                         },
	{ F_DUPFD_CLOEXEC,                  "F_DUPFD_CLOEXEC"                 },
	{ F_GETNOSIGPIPE,                   "F_GETNOSIGPIPE"                  },
	{ F_SETNOSIGPIPE,                   "F_SETNOSIGPIPE"                  },
	{ FD_CLOEXEC,                       "FD_CLOEXEC"                      },
	{ F_RDLCK,                          "F_RDLCK"                         },
	{ F_UNLCK,                          "F_UNLCK"                         },
	{ F_WRLCK,                          "F_WRLCK"                         },
	{ F_PARAM_MASK,                     "F_PARAM_MASK"                    },
	{ F_PARAM_MAX,                      "F_PARAM_MAX"                     },
	{ F_FSCTL,                          "F_FSCTL"                         },
	{ F_FSVOID,                         "F_FSVOID"                        },
	{ F_FSOUT,                          "F_FSOUT"                         },
	{ F_FSIN,                           "F_FSIN"                          },
	{ F_FSINOUT,                        "F_FSINOUT"                       },
	{ F_FSDIRMASK,                      "F_FSDIRMASK"                     },
	{ F_FSPRIV,                         "F_FSPRIV"                        },
	{ LOCK_SH,                          "LOCK_SH"                         },
	{ LOCK_EX,                          "LOCK_EX"                         },
	{ LOCK_NB,                          "LOCK_NB"                         },
	{ LOCK_UN,                          "LOCK_UN"                         },
	{ SEEK_SET,                         "SEEK_SET"                        },
	{ SEEK_CUR,                         "SEEK_CUR"                        },
	{ SEEK_END,                         "SEEK_END"                        },
	{ POSIX_FADV_NORMAL,                "POSIX_FADV_NORMAL"               },
	{ POSIX_FADV_RANDOM,                "POSIX_FADV_RANDOM"               },
	{ POSIX_FADV_SEQUENTIAL,            "POSIX_FADV_SEQUENTIAL"           },
	{ POSIX_FADV_WILLNEED,              "POSIX_FADV_WILLNEED"             },
	{ POSIX_FADV_DONTNEED,              "POSIX_FADV_DONTNEED"             },
	{ POSIX_FADV_NOREUSE,               "POSIX_FADV_NOREUSE"              },

	/* /usr/include/sys/unistd.h */
	{ F_OK,                             "F_OK"                            },
	{ X_OK,                             "X_OK"                            },
	{ W_OK,                             "W_OK"                            },
	{ R_OK,                             "R_OK"                            },
	{ SEEK_SET,                         "SEEK_SET"                        },
	{ SEEK_CUR,                         "SEEK_CUR"                        },
	{ SEEK_END,                         "SEEK_END"                        },
	{ L_SET,                            "L_SET"                           },
	{ L_INCR,                           "L_INCR"                          },
	{ L_XTND,                           "L_XTND"                          },
	{ FDATASYNC,                        "FDATASYNC"                       },
	{ FFILESYNC,                        "FFILESYNC"                       },
	{ FDISKSYNC,                        "FDISKSYNC"                       },

	/* /usr/include/sys/socket.h */
	{ MSG_OOB,                          "MSG_OOB"                         },
	{ MSG_PEEK,                         "MSG_PEEK"                        },
	{ MSG_DONTROUTE,                    "MSG_DONTROUTE"                   },
	{ MSG_EOR,                          "MSG_EOR"                         },
	{ MSG_TRUNC,                        "MSG_TRUNC"                       },
	{ MSG_CTRUNC,                       "MSG_CTRUNC"                      },
	{ MSG_WAITALL,                      "MSG_WAITALL"                     },
	{ MSG_DONTWAIT,                     "MSG_DONTWAIT"                    },
	{ MSG_BCAST,                        "MSG_BCAST"                       },
	{ MSG_MCAST,                        "MSG_MCAST"                       },
	{ MSG_NOSIGNAL,                     "MSG_NOSIGNAL"                    },
	{ MSG_CMSG_CLOEXEC,                 "MSG_CMSG_CLOEXEC"                },
	{ MSG_NBIO,                         "MSG_NBIO"                        },

	/* /usr/include/sys/filio.h */
	{ FIOCLEX,                          "FIOCLEX"                         },
	{ FIONCLEX,                         "FIONCLEX"                        },
	{ FIONREAD,                         "FIONREAD"                        },
	{ FIONBIO,                          "FIONBIO"                         },
	{ FIOASYNC,                         "FIOASYNC"                        },
	{ FIOSETOWN,                        "FIOSETOWN"                       },
	{ FIOGETOWN,                        "FIOGETOWN"                       },
	{ FIOGETBMAP,                       "FIOGETBMAP"                      },
	{ FIONWRITE,                        "FIONWRITE"                       },
	{ FIONSPACE,                        "FIONSPACE"                       },
	{ FIBMAP,                           "FIBMAP"                          },

	/* /usr/include/sys/poll.h */
	{ POLLIN,                           "POLLIN"                          },
	{ POLLPRI,                          "POLLPRI"                         },
	{ POLLOUT,                          "POLLOUT"                         },
	{ POLLRDNORM,                       "POLLRDNORM"                      },
	{ POLLWRNORM,                       "POLLWRNORM"                      },
	{ POLLRDBAND,                       "POLLRDBAND"                      },
	{ POLLWRBAND,                       "POLLWRBAND"                      },
	{ POLLERR,                          "POLLERR"                         },
	{ POLLHUP,                          "POLLHUP"                         },
	{ POLLNVAL,                         "POLLNVAL"                        },

	/* /usr/include/sys/errno.h */
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
	{ EDEADLK,                          "EDEADLK"                         },
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
	{ EAGAIN,                           "EAGAIN"                          },
	{ EWOULDBLOCK,                      "EWOULDBLOCK"                     },
	{ EINPROGRESS,                      "EINPROGRESS"                     },
	{ EALREADY,                         "EALREADY"                        },
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
	{ ELOOP,                            "ELOOP"                           },
	{ ENAMETOOLONG,                     "ENAMETOOLONG"                    },
	{ EHOSTDOWN,                        "EHOSTDOWN"                       },
	{ EHOSTUNREACH,                     "EHOSTUNREACH"                    },
	{ ENOTEMPTY,                        "ENOTEMPTY"                       },
	{ EPROCLIM,                         "EPROCLIM"                        },
	{ EUSERS,                           "EUSERS"                          },
	{ EDQUOT,                           "EDQUOT"                          },
	{ ESTALE,                           "ESTALE"                          },
	{ EREMOTE,                          "EREMOTE"                         },
	{ EBADRPC,                          "EBADRPC"                         },
	{ ERPCMISMATCH,                     "ERPCMISMATCH"                    },
	{ EPROGUNAVAIL,                     "EPROGUNAVAIL"                    },
	{ EPROGMISMATCH,                    "EPROGMISMATCH"                   },
	{ EPROCUNAVAIL,                     "EPROCUNAVAIL"                    },
	{ ENOLCK,                           "ENOLCK"                          },
	{ ENOSYS,                           "ENOSYS"                          },
	{ EFTYPE,                           "EFTYPE"                          },
	{ EAUTH,                            "EAUTH"                           },
	{ ENEEDAUTH,                        "ENEEDAUTH"                       },
	{ EIDRM,                            "EIDRM"                           },
	{ ENOMSG,                           "ENOMSG"                          },
	{ EOVERFLOW,                        "EOVERFLOW"                       },
	{ EILSEQ,                           "EILSEQ"                          },
	{ ENOTSUP,                          "ENOTSUP"                         },
	{ ECANCELED,                        "ECANCELED"                       },
	{ EBADMSG,                          "EBADMSG"                         },
	{ ENODATA,                          "ENODATA"                         },
	{ ENOSR,                            "ENOSR"                           },
	{ ENOSTR,                           "ENOSTR"                          },
	{ ETIME,                            "ETIME"                           },
	{ ENOATTR,                          "ENOATTR"                         },
	{ EMULTIHOP,                        "EMULTIHOP"                       },
	{ ENOLINK,                          "ENOLINK"                         },
	{ EPROTO,                           "EPROTO"                          },
	{ ELAST,                            "ELAST"                           },

	/* Sentinel marking the end of the table. */
	{ 0, NULL },
};

struct int_symbol *platform_symbols(void)
{
	return platform_symbols_table;
}

#endif  /* __NetBSD__ */

