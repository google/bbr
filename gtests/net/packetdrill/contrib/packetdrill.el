(setq packetdrill-keywords '("sa_family" "sin_port" "sin_addr" "msg_name" "msg_iov" "msg_flags" "fd" "events" "revents" "htons" "icmp" "udp" "inet_addr" "inet6_addr" "ack" "eol" "ecr" "mss" "mtu" "nop" "sack" "sackOK" "TS" "FO" "FOEXP" "val" "win" "wscale" "ect01" "ect0" "ect1" "noecn" "ce"))

(setq packetdrill-constants '("AF_INET" "AF_INET6" "AF_PACKET" "PF_INET" "PF_INET6" "SOCK_RAW" "SOCK_STREAM" "SOCK_DGRAM" "IPPROTO_RAW" "IPPROTO_IP" "IPPROTO_IPV6" "IPPROTO_ICMP" "IPPROTO_TCP" "IPPROTO_UDP" "SOL_SOCKET" "SOL_IP" "SOL_IPV6" "SOL_TCP" "SOL_UDP" "SO_ACCEPTCONN" "SO_ATTACH_FILTER" "SO_BINDTODEVICE" "SO_BROADCAST" "SO_BSDCOMPAT" "SO_DEBUG" "SO_DETACH_FILTER" "SO_DONTROUTE" "SO_ERROR" "SO_KEEPALIVE" "SO_LINGER" "SO_NO_CHECK" "SO_OOBINLINE" "SO_PASSCRED" "SO_PEERCRED" "SO_PEERNAME" "SO_PEERSEC" "SO_PRIORITY" "SO_RCVBUF" "SO_RCVLOWAT" "SO_RCVTIMEO" "SO_REUSEADDR" "SO_REUSEPORT" "SO_SECURITY_AUTHENTICATION" "SO_SECURITY_ENCRYPTION_NETWORK" "SO_SECURITY_ENCRYPTION_TRANSPORT" "SO_SNDBUF" "SO_SNDLOWAT" "SO_SNDTIMEO" "SO_TIMESTAMP" "SO_TYPE" "SO_MAX_PACING_RATE" "SO_ZEROCOPY" "IP_TOS" "IP_MTU_DISCOVER" "IP_PMTUDISC_WANT" "IP_PMTUDISC_DONT" "IP_PMTUDISC_DO" "IP_PMTUDISC_PROBE" "IP_MTU" "IPV6_MTU" "TCP_NODELAY" "TCP_MAXSEG" "TCP_CORK" "TCP_KEEPIDLE" "TCP_KEEPINTVL" "TCP_KEEPCNT" "TCP_SYNCNT" "TCP_LINGER2" "TCP_DEFER_ACCEPT" "TCP_INFO" "TCP_QUICKACK" "TCP_CONGESTION" "TCP_MD5SIG" "TCP_COOKIE_TRANSACTIONS" "TCP_THIN_LINEAR_TIMEOUTS" "TCP_THIN_DUPACK" "TCP_USER_TIMEOUT" "TCP_CWND" "TCP_SAVE_SYN" "TCP_SAVED_SYN" "TCP_FASTOPEN" "TCP_FASTOPEN_CONNECT" "TCP_TX_DELAY" "TCP_MULTIPLE_CONNECTIONS" "O_RDONLY" "O_WRONLY" "O_RDWR" "O_ACCMODE" "O_CREAT" "O_EXCL" "O_NOCTTY" "O_TRUNC" "O_APPEND" "O_NONBLOCK" "F_DUPFD" "F_GETFD" "F_SETFD" "F_GETFL" "F_SETFL" "F_GETLK" "F_SETLK" "F_SETLKW" "F_GETOWN" "F_SETOWN" "F_SETSIG" "F_GETSIG" "F_GETOWN" "F_SETOWN" "F_SETLK" "F_SETLKW" "F_GETLK" "F_SETLK64" "F_SETLKW64" "F_GETLK64" "F_SETLEASE" "F_GETLEASE" "F_NOTIFY" "F_DUPFD_CLOEXEC" "FD_CLOEXEC" "LOCK_SH" "LOCK_EX" "LOCK_NB" "LOCK_UN" "F_RDLCK" "F_WRLCK" "F_UNLCK" "F_EXLCK" "F_SHLCK" "SEEK_SET" "SEEK_CUR" "SEEK_END" "MSG_OOB" "MSG_DONTROUTE" "MSG_PEEK" "MSG_CTRUNC" "MSG_PROXY" "MSG_EOR" "MSG_WAITALL" "MSG_TRUNC" "MSG_CTRUNC" "MSG_ERRQUEUE" "MSG_DONTWAIT" "MSG_CONFIRM" "MSG_FIN" "MSG_SYN" "MSG_RST" "MSG_NOSIGNAL" "MSG_MORE" "MSG_CMSG_CLOEXEC" "MSG_FASTOPEN" "MSG_ZEROCOPY" "SIOCINQ" "FIONREAD" "POLLIN" "POLLPRI" "POLLOUT" "POLLRDNORM" "POLLRDBAND" "POLLWRNORM" "POLLWRBAND" "POLLMSG" "POLLREMOVE" "POLLRDHUP" "POLLERR" "POLLHUP" "POLLNVAL" "EPERM" "ENOENT" "ESRCH" "EINTR" "EIO" "ENXIO" "E2BIG" "ENOEXEC" "EBADF" "ECHILD" "EAGAIN" "ENOMEM" "EACCES" "EFAULT" "ENOTBLK" "EBUSY" "EEXIST" "EXDEV" "ENODEV" "ENOTDIR" "EISDIR" "EINVAL" "ENFILE" "EMFILE" "ENOTTY" "ETXTBSY" "EFBIG" "ENOSPC" "ESPIPE" "EROFS" "EMLINK" "EPIPE" "EDOM" "ERANGE" "EDEADLK" "ENAMETOOLONG" "ENOLCK" "ENOSYS" "ENOTEMPTY" "ELOOP" "EWOULDBLOCK" "ENOMSG" "EIDRM" "ECHRNG" "EL2NSYNC" "EL3HLT" "EL3RST" "ELNRNG" "EUNATCH" "ENOCSI" "EL2HLT" "EBADE" "EBADR" "EXFULL" "ENOANO" "EBADRQC" "EBADSLT" "EDEADLOCK" "EBFONT" "ENOSTR" "ENODATA" "ETIME" "ENOSR" "ENONET" "ENOPKG" "EREMOTE" "ENOLINK" "EADV" "ESRMNT" "ECOMM" "EPROTO" "EMULTIHOP" "EDOTDOT" "EBADMSG" "EOVERFLOW" "ENOTUNIQ" "EBADFD" "EREMCHG" "ELIBACC" "ELIBBAD" "ELIBSCN" "ELIBMAX" "ELIBEXEC" "EILSEQ" "ERESTART" "ESTRPIPE" "EUSERS" "ENOTSOCK" "EDESTADDRREQ" "EMSGSIZE" "EPROTOTYPE" "ENOPROTOOPT" "EPROTONOSUPPORT" "ESOCKTNOSUPPORT" "EOPNOTSUPP" "EPFNOSUPPORT" "EAFNOSUPPORT" "EADDRINUSE" "EADDRNOTAVAIL" "ENETDOWN" "ENETUNREACH" "ENETRESET" "ECONNABORTED" "ECONNRESET" "ENOBUFS" "EISCONN" "ENOTCONN" "ESHUTDOWN" "ETOOMANYREFS" "ETIMEDOUT" "ECONNREFUSED" "EHOSTDOWN" "EHOSTUNREACH" "EALREADY" "EINPROGRESS" "ESTALE" "EUCLEAN" "ENOTNAM" "ENAVAIL" "EISNAM" "EREMOTEIO" "EDQUOT" "ENOMEDIUM" "EMEDIUMTYPE" "ECANCELED" "ENOKEY" "EKEYEXPIRED" "EKEYREVOKED" "EKEYREJECTED" "EOWNERDEAD" "ENOTRECOVERABLE" "ERFKILL" "POLLIN" "POLLPRI" "POLLOUT" "POLLRDNORM" "POLLRDBAND" "POLLWRNORM" "POLLWRBAND" "POLLMSG" "POLLREMOVE" "POLLRDHUP" "POLLERR" "POLLHUP" "POLLNVAL"))

(setq packetdrill-functions '("accept" "bind" "close" "connect" "fcntl" "getsockopt" "ioctl" "listen" "poll" "read" "readv" "recv" "recvfrom" "recvmsg" "send" "sendmsg" "sendto" "setsockopt" "shutdown" "socket" "write" "writev"))

;; create the regex string for each class of keywords
(setq packetdrill-keywords-regexp (regexp-opt packetdrill-keywords 'words))
(setq packetdrill-constant-regexp (regexp-opt packetdrill-constants 'words))
(setq packetdrill-functions-regexp (regexp-opt packetdrill-functions 'words))

;; clear memory
(setq packetdrill-keywords nil)
(setq packetdrill-constants nil)
(setq packetdrill-functions nil)

;; create the list for font-lock.
;; each class of keyword is given a particular face
(setq packetdrill-font-lock-keywords
  `(
    ("%{\\(.*\\n?\\)*}%" . font-lock-string-face)
    ("`\\(.*\\n?\\)*`" . font-lock-warning-face)
    ("\\.\\.\\." . font-lock-type-face)
    ("\\s-<\\s-" . font-lock-warning-face)
    ("\\s->\\s-" . font-lock-keyword-face)
    (,packetdrill-constant-regexp . font-lock-constant-face)
    (,packetdrill-functions-regexp . font-lock-function-name-face)
    (,packetdrill-keywords-regexp . font-lock-preprocessor-face)
    ))

;; define the mode
(define-derived-mode packetdrill-mode c-mode
  "packetdrill mode"
  "Major mode for editing packetdrill scripts"
  ;; code for syntax highlighting
  (setq font-lock-defaults '((packetdrill-font-lock-keywords)))

  ;; clear memory
  (setq packetdrill-keywords-regexp nil)
  (setq packetdrill-types-regexp nil)
  (setq packetdrill-constants-regexp nil)
  (setq packetdrill-functions-regexp nil)
  )

(provide 'packetdrill-mode)
