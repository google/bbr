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
 * Definitions of strace-style symbols for FreeBSD.
 * Allows us to map from symbolic strings to integers for system call inputs.
 */

#if defined(__FreeBSD__)

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
	{ SO_TIMESTAMP,                     "SO_TIMESTAMP"                    },
	{ SO_NOSIGPIPE,                     "SO_NOSIGPIPE"                    },
	{ SO_ACCEPTFILTER,                  "SO_ACCEPTFILTER"                 },
	{ SO_BINTIME,                       "SO_BINTIME"                      },
	{ SO_NO_OFFLOAD,                    "SO_NO_OFFLOAD"                   },
	{ SO_NO_DDP,                        "SO_NO_DDP"                       },
	{ SO_SNDBUF,                        "SO_SNDBUF"                       },
	{ SO_RCVBUF,                        "SO_RCVBUF"                       },
	{ SO_SNDLOWAT,                      "SO_SNDLOWAT"                     },
	{ SO_RCVLOWAT,                      "SO_RCVLOWAT"                     },
	{ SO_SNDTIMEO,                      "SO_SNDTIMEO"                     },
	{ SO_RCVTIMEO,                      "SO_RCVTIMEO"                     },
	{ SO_ERROR,                         "SO_ERROR"                        },
	{ SO_TYPE,                          "SO_TYPE"                         },
	{ SO_LABEL,                         "SO_LABEL"                        },
	{ SO_PEERLABEL,                     "SO_PEERLABEL"                    },
	{ SO_LISTENQLIMIT,                  "SO_LISTENQLIMIT"                 },
	{ SO_LISTENQLEN,                    "SO_LISTENQLEN"                   },
	{ SO_LISTENINCQLEN,                 "SO_LISTENINCQLEN"                },
	{ SO_SETFIB,                        "SO_SETFIB"                       },
	{ SO_USER_COOKIE,                   "SO_USER_COOKIE"                  },

	/* /usr/include/netinet/tcp.h */
	{ TCP_NODELAY,                      "TCP_NODELAY"                     },
	{ TCP_MAXSEG,                       "TCP_MAXSEG"                      },
	{ TCP_NOPUSH,                       "TCP_NOPUSH"                      },
	{ TCP_NOOPT,                        "TCP_NOOPT"                       },
	{ TCP_MD5SIG,                       "TCP_MD5SIG"                      },
	{ TCP_INFO,                         "TCP_INFO"                        },
	{ TCP_CONGESTION,                   "TCP_CONGESTION"                  },

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
	{ O_FSYNC,                          "O_FSYNC"                         },
	{ O_SYNC,                           "O_SYNC"                          },
	{ O_NOFOLLOW,                       "O_NOFOLLOW"                      },
	{ O_CREAT,                          "O_CREAT"                         },
	{ O_TRUNC,                          "O_TRUNC"                         },
	{ O_EXCL,                           "O_EXCL"                          },
	{ O_NOCTTY,                         "O_NOCTTY"                        },
	{ O_DIRECT,                         "O_DIRECT"                        },
	{ O_DIRECTORY,                      "O_DIRECTORY"                     },
	{ O_EXEC,                           "O_EXEC"                          },
	{ O_TTY_INIT,                       "O_TTY_INIT"                      },
	{ O_CLOEXEC,                        "O_CLOEXEC"                       },
	{ FAPPEND,                          "FAPPEND"                         },
	{ FASYNC,                           "FASYNC"                          },
	{ FFSYNC,                           "FFSYNC"                          },
	{ FNONBLOCK,                        "FNONBLOCK"                       },
	{ FNDELAY,                          "FNDELAY"                         },
	{ O_NDELAY,                         "O_NDELAY"                        },
	{ FRDAHEAD,                         "FRDAHEAD"                        },
	{ AT_FDCWD,                         "AT_FDCWD"                        },
	{ AT_EACCESS,                       "AT_EACCESS"                      },
	{ AT_SYMLINK_NOFOLLOW,              "AT_SYMLINK_NOFOLLOW"             },
	{ AT_SYMLINK_FOLLOW,                "AT_SYMLINK_FOLLOW"               },
	{ AT_REMOVEDIR,                     "AT_REMOVEDIR"                    },
	{ F_DUPFD,                          "F_DUPFD"                         },
	{ F_GETFD,                          "F_GETFD"                         },
	{ F_SETFD,                          "F_SETFD"                         },
	{ F_GETFL,                          "F_GETFL"                         },
	{ F_SETFL,                          "F_SETFL"                         },
	{ F_GETOWN,                         "F_GETOWN"                        },
	{ F_SETOWN,                         "F_SETOWN"                        },
	{ F_OGETLK,                         "F_OGETLK"                        },
	{ F_OSETLK,                         "F_OSETLK"                        },
	{ F_OSETLKW,                        "F_OSETLKW"                       },
	{ F_DUP2FD,                         "F_DUP2FD"                        },
	{ F_GETLK,                          "F_GETLK"                         },
	{ F_SETLK,                          "F_SETLK"                         },
	{ F_SETLKW,                         "F_SETLKW"                        },
	{ F_SETLK_REMOTE,                   "F_SETLK_REMOTE"                  },
	{ F_READAHEAD,                      "F_READAHEAD"                     },
	{ F_RDAHEAD,                        "F_RDAHEAD"                       },
	{ FD_CLOEXEC,                       "FD_CLOEXEC"                      },
	{ F_RDLCK,                          "F_RDLCK"                         },
	{ F_UNLCK,                          "F_UNLCK"                         },
	{ F_WRLCK,                          "F_WRLCK"                         },
	{ F_UNLCKSYS,                       "F_UNLCKSYS"                      },
	{ F_CANCEL,                         "F_CANCEL"                        },
	{ LOCK_SH,                          "LOCK_SH"                         },
	{ LOCK_EX,                          "LOCK_EX"                         },
	{ LOCK_NB,                          "LOCK_NB"                         },
	{ LOCK_UN,                          "LOCK_UN"                         },

	/* /usr/include/sys/unistd.h */
	{ SEEK_SET,                         "SEEK_SET"                        },
	{ SEEK_CUR,                         "SEEK_CUR"                        },
	{ SEEK_END,                         "SEEK_END"                        },

	/* /usr/include/sys/socket.h */
	{ MSG_OOB,                          "MSG_OOB"                         },
	{ MSG_PEEK,                         "MSG_PEEK"                        },
	{ MSG_DONTROUTE,                    "MSG_DONTROUTE"                   },
	{ MSG_EOR,                          "MSG_EOR"                         },
	{ MSG_TRUNC,                        "MSG_TRUNC"                       },
	{ MSG_CTRUNC,                       "MSG_CTRUNC"                      },
	{ MSG_WAITALL,                      "MSG_WAITALL"                     },
	{ MSG_NOTIFICATION,                 "MSG_NOTIFICATION"                },
	{ MSG_DONTWAIT,                     "MSG_DONTWAIT"                    },
	{ MSG_EOF,                          "MSG_EOF"                         },
	{ MSG_NBIO,                         "MSG_NBIO"                        },
	{ MSG_COMPAT,                       "MSG_COMPAT"                      },
	{ MSG_NOSIGNAL,                     "MSG_NOSIGNAL"                    },

	/* /usr/include/sys/filio.h */
	{ FIOCLEX,                          "FIOCLEX"                         },
	{ FIONCLEX,                         "FIONCLEX"                        },
	{ FIONREAD,                         "FIONREAD"                        },
	{ FIONBIO,                          "FIONBIO"                         },
	{ FIOASYNC,                         "FIOASYNC"                        },
	{ FIOSETOWN,                        "FIOSETOWN"                       },
	{ FIOGETOWN,                        "FIOGETOWN"                       },
	{ FIODTYPE,                         "FIODTYPE"                        },
	{ FIOGETLBA,                        "FIOGETLBA"                       },
	{ FIODGNAME,                        "FIODGNAME"                       },
	{ FIONWRITE,                        "FIONWRITE"                       },
	{ FIONSPACE,                        "FIONSPACE"                       },
	{ FIOSEEKDATA,                      "FIOSEEKDATA"                     },
	{ FIOSEEKHOLE,                      "FIOSEEKHOLE"                     },

	/* /usr/include/sys/poll.h */
	{ POLLIN,                           "POLLIN"                          },
	{ POLLPRI,                          "POLLPRI"                         },
	{ POLLOUT,                          "POLLOUT"                         },
	{ POLLRDNORM,                       "POLLRDNORM"                      },
	{ POLLWRNORM,                       "POLLWRNORM"                      },
	{ POLLRDBAND,                       "POLLRDBAND"                      },
	{ POLLWRBAND,                       "POLLWRBAND"                      },
	{ POLLINIGNEOF,                     "POLLINIGNEOF"                    },
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
	{ ENOTSUP,                          "ENOTSUP"                         },
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
	{ ECANCELED,                        "ECANCELED"                       },
	{ EILSEQ,                           "EILSEQ"                          },
	{ ENOATTR,                          "ENOATTR"                         },
	{ EDOOFUS,                          "EDOOFUS"                         },
	{ EBADMSG,                          "EBADMSG"                         },
	{ EMULTIHOP,                        "EMULTIHOP"                       },
	{ ENOLINK,                          "ENOLINK"                         },
	{ EPROTO,                           "EPROTO"                          },
	{ ENOTCAPABLE,                      "ENOTCAPABLE"                     },
	{ ECAPMODE,                         "ECAPMODE"                        },

	/* Sentinel marking the end of the table. */
	{ 0, NULL },
};

struct int_symbol *platform_symbols(void)
{
	return platform_symbols_table;
}

#endif  /* __FreeBSD__ */
